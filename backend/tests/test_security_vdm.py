"""Regression tests for bounded RMDX expansion and import workers."""

import io
import struct
import unittest
from unittest.mock import patch
import zlib

from defender_sig_extractor.vdm_parser import VDMParser, VDMSizeLimitError


LAYOUTS = ("primary", "fallback_raw", "fallback_zlib", "search")


def make_vdm(payload, layout="primary", declared_size=64):
    compressor = zlib.compressobj(wbits=-15 if layout in ("primary", "fallback_raw") else 15)
    compressed = compressor.compress(payload) + compressor.flush()
    header = bytearray(40)
    header[:4] = b"RMDX"
    if layout == "primary":
        struct.pack_into("<II", header, 24, 32, declared_size)
    elif layout.startswith("fallback"):
        struct.pack_into("<II", header, 8, len(header), len(compressed))
    return bytes(header) + compressed


class VDMParserTests(unittest.TestCase):
    def parse(self, data, **limits):
        with patch("builtins.open", return_value=io.BytesIO(data)):
            return VDMParser("fixture.vdm", **limits).decompress()

    def test_every_layout_preserves_valid_tlv_and_exact_limit(self):
        payload = struct.pack("<BBH", 0xA0, 5, 0) + b"hello"
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                data = make_vdm(payload, layout)
                with patch("builtins.open", return_value=io.BytesIO(data)):
                    parser = VDMParser("fixture.vdm", max_file_size=len(data),
                                       max_decompressed_size=len(payload))
                    self.assertEqual(parser.decompress(), payload)
                    self.assertIs(parser.decompress(), parser.get_decompressed_data())
                    signatures = list(parser.parse_tlv_stream())
                self.assertEqual([(s.sig_type, s.data) for s in signatures], [(0xA0, b"hello")])

    def test_high_expansion_and_forged_lengths_cannot_bypass_limit(self):
        payload = b"A" * (16 * 1024 * 1024)
        for layout in LAYOUTS:
            for claimed in (0, 64, 0xFFFFFFFF):
                with self.subTest(layout=layout, declared_size=claimed):
                    data = make_vdm(payload, layout, claimed)
                    self.assertLess(len(data), 17000)
                    with self.assertRaises(VDMSizeLimitError):
                        self.parse(data, max_decompressed_size=1024 * 1024)

    def test_output_limit_plus_one_is_rejected_without_partial_output(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                output = io.BytesIO(b"old output")
                with patch("builtins.open", return_value=io.BytesIO(make_vdm(b"A" * 1025, layout))):
                    parser = VDMParser("fixture.vdm", max_decompressed_size=1024)
                    with self.assertRaises(VDMSizeLimitError):
                        parser.decompress_to(output)
                    self.assertIsNone(parser._decompressed)
                self.assertEqual(output.getvalue(), b"")

    def test_limit_error_does_not_try_a_later_valid_stream(self):
        bomb = make_vdm(b"A" * 10000)
        # Put a benign zlib candidate in the header-search range, preceding the
        # primary stream. An over-budget primary must not fall through to it.
        data = bytearray(bomb[:40] + zlib.compress(b"benign") + bomb[40:])
        struct.pack_into("<I", data, 24, 32 + len(zlib.compress(b"benign")))
        with self.assertRaises(VDMSizeLimitError):
            self.parse(data, max_decompressed_size=1024)

    def test_chunk_boundaries_empty_stream_and_trailing_pe_data(self):
        for size in (0, 65535, 65536, 65537, 131072):
            payload = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
            for layout in LAYOUTS:
                with self.subTest(layout=layout, size=size):
                    self.assertEqual(self.parse(make_vdm(payload, layout) + b"PE trailer",
                                                max_decompressed_size=max(1, size)), payload)

    def test_buffered_output_is_drained_after_all_input_is_consumed(self):
        for payload in (b"A" * 65537, b"\xa0\x02\x00\x00AA" * 10923,
                        bytes(65540), b"A" * 131073):
            for layout in LAYOUTS:
                with self.subTest(layout=layout, size=len(payload)):
                    self.assertEqual(self.parse(make_vdm(payload, layout),
                                                max_decompressed_size=len(payload)), payload)

    def test_truncated_streams_and_invalid_spans_are_rejected(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout), self.assertRaises(ValueError):
                self.parse(make_vdm(b"A" * 100000, layout)[:-1])
        data = bytearray(make_vdm(b"valid", "fallback_raw"))
        struct.pack_into("<I", data, 12, len(data) + 1)
        with self.assertRaises(ValueError):
            self.parse(data)
        data = bytearray(make_vdm(b"valid"))
        struct.pack_into("<I", data, 24, 0xFFFFFFFF)
        with self.assertRaises(ValueError):
            self.parse(data)

    def test_file_limit_bounds_the_read_even_without_stat(self):
        class Input(io.BytesIO):
            def read(self, size=-1):
                self_limit.assertEqual(size, 65)
                return super().read(size)

        self_limit = self
        with patch("builtins.open", return_value=Input(b"A" * 1000)):
            with self.assertRaises(VDMSizeLimitError):
                VDMParser("fixture.vdm", max_file_size=64).decompress()


if __name__ == "__main__":
    unittest.main()
