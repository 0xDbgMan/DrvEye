"""Unit tests for the minimal DER walker and Authenticode helpers."""

import unittest

from drivertool.authenticode import (
    _decode_oid,
    _tlv,
    parse_signed_data,
    compute_authenticode_hash,
)


class TestDERWalker(unittest.TestCase):
    """Tests for the minimal ASN.1/DER primitives."""

    def test_tlv_short_length(self):
        # SEQUENCE with length 2 containing two INTEGER 0x01
        data = bytes([0x30, 0x02, 0x01, 0x01, 0x01, 0x01])
        tag, hl, cl, tl = _tlv(data, 0)
        self.assertEqual(tag, 0x30)
        self.assertEqual(hl, 2)
        self.assertEqual(cl, 2)
        self.assertEqual(tl, 4)

    def test_tlv_long_length(self):
        # OCTET STRING with 0x82 long-length header (256 bytes)
        payload = b"\x00" * 256
        data = bytes([0x04, 0x82, 0x01, 0x00]) + payload
        tag, hl, cl, tl = _tlv(data, 0)
        self.assertEqual(tag, 0x04)
        self.assertEqual(hl, 4)
        self.assertEqual(cl, 256)
        self.assertEqual(tl, 260)

    def test_tlv_past_end_raises(self):
        with self.assertRaises(ValueError):
            _tlv(b"\x30", 0)

    def test_decode_oid_sha256(self):
        self.assertEqual(
            _decode_oid(bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])),
            "2.16.840.1.101.3.4.2.1",
        )

    def test_decode_oid_empty(self):
        self.assertEqual(_decode_oid(b""), "")


class TestParseSignedData(unittest.TestCase):
    """Tests for PKCS#7 SignedData parsing."""

    def test_empty_returns_none(self):
        self.assertIsNone(parse_signed_data(b""))

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_signed_data(b"DEADBEEF" * 8))

    def test_wrong_oid_returns_none(self):
        # SEQUENCE { OID(1.2.840.113549.1.7.1) = data, not signedData }
        # ContentInfo: sequence { oid, content[0] }
        oid_data = bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])
        content = bytes([0xA0, 0x02, 0x05, 0x00])  # [0] EXPLICIT NULL
        seq = bytes([0x30, len(oid_data) + len(content)]) + oid_data + content
        self.assertIsNone(parse_signed_data(seq))


class TestComputeAuthenticodeHash(unittest.TestCase):
    """Tests for Authenticode hash computation."""

    def test_none_on_garbage(self):
        # compute_authenticode_hash needs a real PE object; with a fake one
        # it should return None rather than crash.
        class FakePE:
            pass

        self.assertIsNone(compute_authenticode_hash(b"notape", FakePE(), "1.3.14.3.2.26"))


if __name__ == "__main__":
    unittest.main()
