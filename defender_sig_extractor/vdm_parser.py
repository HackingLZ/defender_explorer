"""
VDM Parser - Parse Microsoft Defender VDM signature files

VDM files are PE files with an embedded RMDX resource containing
compressed signature data in TLV (Type-Length-Value) format.
"""

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional, BinaryIO
import io

try:
    import pefile
except ImportError:
    pefile = None

from .signature_types import get_type_name, is_lua_type


# VDM format constants
RMDX_SIGNATURE = b'RMDX'
RSTR_SIGNATURE = b'RSTR'

# Apply to every caller, including the standalone extractor. Header lengths are
# untrusted and must never determine the allocation budget.
MAX_VDM_FILE_SIZE = 256 * 1024 * 1024
MAX_VDM_DECOMPRESSED_SIZE = 512 * 1024 * 1024
_DECOMPRESS_CHUNK_SIZE = 64 * 1024


class VDMSizeLimitError(ValueError):
    """The VDM exceeds its input or expanded-data budget."""


@dataclass
class Signature:
    """Represents a single signature entry from VDM."""
    sig_type: int
    size: int
    data: bytes
    offset: int  # Offset in decompressed stream

    @property
    def type_name(self) -> str:
        return get_type_name(self.sig_type)

    @property
    def is_lua(self) -> bool:
        return is_lua_type(self.sig_type)

    def __repr__(self) -> str:
        return f"Signature({self.type_name}, size={self.size}, offset=0x{self.offset:x})"


@dataclass
class VDMInfo:
    """Information about a VDM file."""
    path: str
    version: Optional[str]
    timestamp: Optional[int]
    compressed_size: int
    decompressed_size: int
    signature_count: int


class VDMParser:
    """Parser for Microsoft Defender VDM signature files."""

    def __init__(self, vdm_path: str, *, max_file_size: int = MAX_VDM_FILE_SIZE,
                 max_decompressed_size: int = MAX_VDM_DECOMPRESSED_SIZE):
        if max_file_size <= 0 or max_decompressed_size <= 0:
            raise ValueError("VDM size limits must be positive")
        self.path = Path(vdm_path)
        self.max_file_size = max_file_size
        self.max_decompressed_size = max_decompressed_size
        self._data: Optional[bytes] = None
        self._decompressed: Optional[bytes] = None
        self._pe = None

    def _load_pe(self) -> None:
        """Load VDM file as PE."""
        if pefile is None:
            raise ImportError("pefile library required: pip install pefile")

        self._pe = pefile.PE(str(self.path))

    def _find_rmdx_resource(self) -> tuple[int, int]:
        """Find RMDX resource in PE file and return (offset, size)."""
        with open(self.path, 'rb') as f:
            data = f.read()

        # Search for RMDX signature
        idx = data.find(RMDX_SIGNATURE)
        if idx == -1:
            raise ValueError(f"RMDX signature not found in {self.path}")

        # RMDX header format:
        # 0x00: 'RMDX' (4 bytes)
        # 0x04: unknown (4 bytes)
        # 0x08: compressed data offset from RMDX (4 bytes)
        # 0x0C: compressed data size (4 bytes)
        # 0x10: decompressed size (4 bytes)

        offset = struct.unpack_from('<I', data, idx + 8)[0]
        size = struct.unpack_from('<I', data, idx + 12)[0]

        return idx + offset, size

    def _find_rmdx_resource_pefile(self) -> tuple[bytes, int, int]:
        """Use pefile to find RMDX resource."""
        if self._pe is None:
            self._load_pe()

        # Read raw file data
        with open(self.path, 'rb') as f:
            data = f.read()

        # Find RMDX header
        idx = data.find(RMDX_SIGNATURE)
        if idx == -1:
            raise ValueError(f"RMDX signature not found in {self.path}")

        # Parse RMDX header
        # Format varies slightly but commonly:
        # RMDX + 8 bytes header + compressed data
        header = data[idx:idx + 32]

        # Try to find the compressed data start
        # Usually starts after a 16-24 byte header
        compressed_offset = idx + 24  # Common offset

        # Look for zlib header (0x78)
        for test_offset in [16, 20, 24, 28, 32]:
            if idx + test_offset < len(data) and data[idx + test_offset] == 0x78:
                compressed_offset = idx + test_offset
                break

        # Read size from header (position varies)
        compressed_size = struct.unpack_from('<I', data, idx + 12)[0]
        decompressed_size = struct.unpack_from('<I', data, idx + 16)[0]

        return data[compressed_offset:], compressed_size, decompressed_size

    def decompress(self) -> bytes:
        """Decompress VDM file and return raw signature data."""
        if self._decompressed is not None:
            return self._decompressed

        with io.BytesIO() as output:
            self.decompress_to(output)
            self._decompressed = output.getvalue()
        return self._decompressed

    def _inflate_to(self, compressed: memoryview, wbits: int, output: BinaryIO) -> None:
        """Inflate one candidate, bounding each allocation and the total output."""
        output.seek(0)
        output.truncate()
        inflater = zlib.decompressobj(wbits)
        total = 0
        for offset in range(0, len(compressed), _DECOMPRESS_CHUNK_SIZE):
            pending = compressed[offset:offset + _DECOMPRESS_CHUNK_SIZE]
            while True:
                limit = min(_DECOMPRESS_CHUNK_SIZE, self.max_decompressed_size - total + 1)
                chunk = inflater.decompress(pending, limit)
                total += len(chunk)
                if total > self.max_decompressed_size:
                    # This is deliberately not zlib.error: no fallback may retry
                    # or reinterpret a stream after it exceeds the budget.
                    raise VDMSizeLimitError("VDM expanded data exceeds its size limit")
                output.write(chunk)
                if inflater.eof:
                    return
                pending = inflater.unconsumed_tail
                if not pending and len(chunk) < limit:
                    break
                # A full output chunk can leave buffered output even when all
                # input was consumed. Drain it with bounded empty-input calls.
        # decompressobj accepts truncated streams unless eof is checked. Never
        # flush without a bound or accept a partial signature database.
        raise zlib.error("Incomplete VDM compressed stream")

    def decompress_to(self, output: BinaryIO) -> None:
        """Write to a seekable binary stream without materializing expanded data.

        The destination is replaced and cleared on failure. Callers must only
        consume it after this method returns successfully.
        """
        try:
            self._decompress_to(output)
        except Exception:
            output.seek(0)
            output.truncate()
            raise

    def _decompress_to(self, output: BinaryIO) -> None:
        with open(self.path, 'rb') as f:
            data = f.read(self.max_file_size + 1)
        if len(data) > self.max_file_size:
            raise VDMSizeLimitError("VDM file exceeds its size limit")

        # Find RMDX header
        idx = data.find(RMDX_SIGNATURE)
        if idx == -1:
            raise ValueError(f"RMDX signature not found in {self.path}")

        view = memoryview(data)

        # Primary layout: offset at +0x18. The length at +0x1C describes
        # expanded data in Microsoft files, not the compressed span. Enforce
        # our actual byte budget regardless of this advisory header value.
        try:
            offset_rel, _ = struct.unpack_from('<II', data, idx + 0x18)

            # The compressed data starts at base + offset + 8 (skip 8-byte header)
            compressed_start = idx + offset_rel + 8
            if idx + 32 <= compressed_start < len(data):
                self._inflate_to(view[compressed_start:], -15, output)
                return
        except (struct.error, zlib.error):
            pass

        # Fallback layout 1: offset at +8, size at +12
        try:
            offset_rel, comp_size = struct.unpack_from('<II', data, idx + 8)
            compressed_start = idx + offset_rel
            compressed_end = compressed_start + comp_size

            if 16 <= offset_rel < 1024 and comp_size > 0 and compressed_end <= len(data):
                compressed = view[compressed_start:compressed_end]
                try:
                    self._inflate_to(compressed, -15, output)
                except zlib.error:
                    self._inflate_to(compressed, zlib.MAX_WBITS, output)
                return
        except (struct.error, zlib.error):
            pass

        # Fallback layout 2: Search for zlib header
        for test_offset in range(idx, min(idx + 64, len(data) - 2)):
            if data[test_offset:test_offset + 2] in (b'\x78\x9c', b'\x78\x01', b'\x78\xda'):
                try:
                    self._inflate_to(view[test_offset:], zlib.MAX_WBITS, output)
                    return
                except zlib.error:
                    continue

        raise ValueError(f"Could not decompress VDM data from {self.path}")

    def parse_tlv_stream(self, data: Optional[bytes] = None) -> Iterator[Signature]:
        """
        Parse TLV (Type-Length-Value) signature stream.

        TLV Entry format:
        - sig_type: uint8   (signature type code)
        - size_low: uint8   (low byte of size)
        - size_high: uint16 (high bytes of size, little-endian)
        - value: bytes[size] (payload data)

        Size = size_low | (size_high << 8)
        """
        if data is None:
            data = self.decompress()

        offset = 0
        while offset + 4 <= len(data):
            # Read TLV header
            sig_type = data[offset]
            size_low = data[offset + 1]
            size_high = struct.unpack_from('<H', data, offset + 2)[0]

            size = size_low | (size_high << 8)

            # Sanity check
            if size > len(data) - offset - 4:
                # Try alternate size calculation
                size = struct.unpack_from('<I', data, offset)[0] >> 8
                if size > len(data) - offset - 4:
                    break

            # Extract payload
            payload_offset = offset + 4
            payload = data[payload_offset:payload_offset + size]

            yield Signature(
                sig_type=sig_type,
                size=size,
                data=payload,
                offset=offset
            )

            offset = payload_offset + size

    def get_info(self) -> VDMInfo:
        """Get information about the VDM file."""
        try:
            decompressed = self.decompress()
            signatures = list(self.parse_tlv_stream(decompressed))
            sig_count = len(signatures)
            decomp_size = len(decompressed)
        except VDMSizeLimitError:
            raise
        except Exception:
            sig_count = 0
            decomp_size = 0

        comp_size = self.path.stat().st_size

        return VDMInfo(
            path=str(self.path),
            version=None,  # TODO: extract from PE version info
            timestamp=None,  # TODO: extract from PE timestamp
            compressed_size=comp_size,
            decompressed_size=decomp_size,
            signature_count=sig_count
        )

    def extract_lua_signatures(self) -> Iterator[Signature]:
        """Extract only Lua-type signatures."""
        for sig in self.parse_tlv_stream():
            if sig.is_lua:
                yield sig

    def get_decompressed_data(self) -> bytes:
        """Get the decompressed VDM data. Alias for decompress()."""
        return self.decompress()


def parse_vdm_file(vdm_path: str) -> Iterator[Signature]:
    """Convenience function to parse a VDM file."""
    parser = VDMParser(vdm_path)
    return parser.parse_tlv_stream()


def decompress_vdm(vdm_path: str) -> bytes:
    """Convenience function to decompress a VDM file."""
    parser = VDMParser(vdm_path)
    return parser.decompress()


class RSTRParser:
    """
    Parser for RSTR format (alternate signature container).

    Some signature files use RSTR instead of RMDX format.
    """

    def __init__(self, data: bytes):
        self.data = data

    def parse(self) -> Iterator[Signature]:
        """Parse RSTR format signature stream."""
        idx = self.data.find(RSTR_SIGNATURE)
        if idx == -1:
            raise ValueError("RSTR signature not found")

        # RSTR format parsing
        # Header: 'RSTR' + metadata + compressed data
        # Structure varies by version

        offset = idx + 4
        # Skip header fields
        while offset < len(self.data) - 4:
            try:
                chunk_type = struct.unpack_from('<I', self.data, offset)[0]
                chunk_size = struct.unpack_from('<I', self.data, offset + 4)[0]

                if chunk_size > len(self.data) - offset:
                    break

                chunk_data = self.data[offset + 8:offset + 8 + chunk_size]

                yield Signature(
                    sig_type=chunk_type & 0xFF,
                    size=chunk_size,
                    data=chunk_data,
                    offset=offset
                )

                offset += 8 + chunk_size
            except struct.error:
                break
