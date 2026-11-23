"""Benign DELTA_BLOB fixtures, including boundary and integrity failures."""
import io
import struct
import unittest
import zlib

from defender_sig_extractor.delta_patcher import apply_delta, delta_blob, patch_to, records


def blob(output, commands):
    return struct.pack('<II', len(output), zlib.crc32(output) ^ 0xffffffff) + commands


def literal(data):
    return b''.join(struct.pack('<H', len(data[i:i+32767])) + data[i:i+32767]
                    for i in range(0, len(data), 32767))


def tlv(kind, data):
    return struct.pack('<I', (len(data) << 8) | kind) + data


class DeltaTests(unittest.TestCase):
    def test_copy_uses_fifteen_bits_plus_six_and_literal_bytes(self):
        base = bytes(range(256)) * 129
        copied = base[2:2+0x8005]
        output = b'prefix' + copied + b'end'
        commands = literal(b'prefix') + struct.pack('<HI', 0xffff, 2) + literal(b'end')
        self.assertEqual(apply_delta(base, blob(output, commands)), output)

    def test_minimum_copy_and_tlv_wrapper(self):
        data = blob(b'abcdef!', struct.pack('<HI', 0x8000, 0) + literal(b'!'))
        wrapped = tlv(0x74, b'metadata') + tlv(0x73, data)
        self.assertEqual(apply_delta(b'abcdef', delta_blob(wrapped)), b'abcdef!')

    def test_rejects_damaged_wrong_base_truncated_and_oversized_patches(self):
        good = blob(b'abcdef', struct.pack('<HI', 0x8000, 0))
        cases = [good[:-1], good+b'\x01', good+b'\x00\x00', good[:4]+b'\x00'*4+good[8:],
                 blob(b'abcdef', struct.pack('<HI', 0x8000, 20)),
                 blob(b'abcdef', b'\x07\x00ab'), b'bad',
                 struct.pack('<II', 100, 0)+literal(b'a')]
        for damaged in cases:
            with self.subTest(damaged=damaged), self.assertRaises(ValueError):
                apply_delta(b'abcdef', damaged)
        with self.assertRaisesRegex(ValueError, 'checksum'):
            apply_delta(b'abcdeg', good)
        with self.assertRaisesRegex(ValueError, 'size limit'):
            patch_to(io.BytesIO(b'abcdef'), good, io.BytesIO(), max_output=5)

    def test_failure_clears_partial_output(self):
        output = io.BytesIO(b'old')
        damaged = blob(b'abcdef', literal(b'abc'))
        with self.assertRaises(ValueError):
            patch_to(io.BytesIO(), damaged, output)
        self.assertEqual(output.getvalue(), b'')

    def test_rejects_partial_or_unrecognized_record_stream(self):
        for data in [b'\x74', tlv(0x74, b'meta')+b'\x73\x10\x00\x00abc', tlv(0x73,b'abc')]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                delta_blob(data)
        with self.assertRaises(ValueError):
            list(records(tlv(1,b'a')+b'x'))
