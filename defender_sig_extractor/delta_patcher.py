"""Checked Microsoft Defender DELTA_BLOB reconstruction.

Format reference: SafeBreach, Black Hat USA 2023, slides 58–73:
https://i.blackhat.com/BH-US-23/Presentations/US-23-Tomer-Defender-Pretender-final.pdf
Copy lengths are (command & 0x7fff) + 6; the header contains output
length and complemented CRC32. Never accept a partial or unchecked result.
"""

import io
import struct
import tempfile
import zlib
from pathlib import Path

from .vdm_parser import VDMParser, MAX_VDM_DECOMPRESSED_SIZE


def records(data):
    """Walk complete TLV records, rejecting truncated headers and payloads."""
    pos = 0
    while pos < len(data):
        if len(data) - pos < 4:
            raise ValueError("Truncated VDM record header")
        header = int.from_bytes(data[pos:pos + 4], "little")
        size, kind = header >> 8, header & 255
        end = pos + 4 + size
        if end > len(data):
            raise ValueError("Truncated VDM record payload")
        yield kind, memoryview(data)[pos + 4:end]
        pos = end


def delta_blob(data):
    entries = list(records(data))
    if [kind for kind, _ in entries] != [0x74, 0x73]:
        raise ValueError("Expected DELTA_BLOB_RECINFO followed by DELTA_BLOB")
    return entries[1][1]


def patch_to(base, blob, output, *, max_output=MAX_VDM_DECOMPRESSED_SIZE):
    """Apply a blob using bounded reads from a seekable expanded base file."""
    if len(blob) < 8:
        raise ValueError("Truncated delta header")
    expected_size, expected_crc = struct.unpack_from("<II", blob)
    if not 0 < expected_size <= max_output:
        raise ValueError("Delta output exceeds its size limit")
    base.seek(0, 2)
    base_size = base.tell()
    pos, written, crc = 8, 0, 0
    try:
        output.seek(0)
        output.truncate()
        while pos < len(blob):
            if len(blob) - pos < 2:
                raise ValueError("Truncated delta command")
            command = struct.unpack_from("<H", blob, pos)[0]
            pos += 2
            if command & 0x8000:
                size = (command & 0x7fff) + 6
                if len(blob) - pos < 4:
                    raise ValueError("Truncated delta copy offset")
                offset = struct.unpack_from("<I", blob, pos)[0]
                pos += 4
                if offset + size > base_size:
                    raise ValueError("Delta copy exceeds base size")
                base.seek(offset)
                chunk = base.read(size)
                if len(chunk) != size:
                    raise ValueError("Incomplete delta base read")
            else:
                size = command
                if not size or pos + size > len(blob):
                    raise ValueError("Invalid delta literal")
                chunk = blob[pos:pos + size]
                pos += size
            written += size
            if written > expected_size:
                raise ValueError("Delta output exceeds declared size")
            output.write(chunk)
            crc = zlib.crc32(chunk, crc)
        if written != expected_size:
            raise ValueError("Delta output size mismatch")
        if (crc ^ 0xffffffff) != expected_crc:
            raise ValueError("Delta output checksum mismatch (wrong base or damaged delta)")
    except Exception:
        output.seek(0)
        output.truncate()
        raise


class DeltaPatcher:
    """Apply a DELTA_BLOB payload to expanded base bytes."""
    def __init__(self, base_data, delta_data):
        self.base, self.delta = base_data, delta_data

    def apply(self):
        with io.BytesIO(self.base) as base, io.BytesIO() as output:
            patch_to(base, self.delta, output)
            return output.getvalue()

    @classmethod
    def patch_files(cls, base_path, delta_path):
        return cls(Path(base_path).read_bytes(), Path(delta_path).read_bytes()).apply()


class VDMDeltaPatcher:
    def __init__(self, base_vdm_path, delta_vdm_path):
        self.base_path, self.delta_path = base_vdm_path, delta_vdm_path

    def apply_to(self, output, *, max_input=None, max_output=MAX_VDM_DECOMPRESSED_SIZE):
        limits = {"max_decompressed_size": max_output}
        if max_input is not None:
            limits["max_file_size"] = max_input
        with tempfile.TemporaryFile() as base:
            VDMParser(self.base_path, **limits).decompress_to(base)
            delta = VDMParser(self.delta_path, **limits).decompress()
            patch_to(base, delta_blob(delta), output, max_output=max_output)

    def apply(self):
        with io.BytesIO() as output:
            self.apply_to(output)
            return output.getvalue()


def apply_delta(base_data, delta_data):
    return DeltaPatcher(base_data, delta_data).apply()


def combine_vdm_files(base_path, delta_path):
    return VDMDeltaPatcher(base_path, delta_path).apply()
