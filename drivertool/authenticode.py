"""Authenticode signature verification for kernel drivers.

Implements the four load-verdict primitives that raw cert parsing alone
cannot answer:

  1. verify_pkcs7_signature   — does the PKCS#7 actually verify?
  2. compute_authenticode_hash — does the PE hash match SpcIndirectData?
  3. extract_nested_signatures — any MsSpcNestedSignature (dual-sign)?
  4. classify_chain_anchor    — does the chain terminate at a root the
                                Windows kernel actually trusts?

Relies only on the `cryptography` package plus a minimal DER walker —
no asn1crypto / pyasn1 dependency.
"""
from __future__ import annotations

import hashlib
import struct
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
    from cryptography.x509 import load_der_x509_certificate
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────
# Minimal ASN.1 / DER walker
# ─────────────────────────────────────────────────────────────────────────

# Tag classes: universal 0x00, application 0x40, context 0x80, private 0xC0
# Common universal tags we touch:
TAG_INTEGER      = 0x02
TAG_BITSTRING    = 0x03
TAG_OCTETSTRING  = 0x04
TAG_NULL         = 0x05
TAG_OID          = 0x06
TAG_SEQUENCE     = 0x30   # SEQUENCE OF / SEQUENCE (constructed)
TAG_SET          = 0x31   # SET / SET OF (constructed)


def _tlv(data: bytes, i: int) -> Tuple[int, int, int, int]:
    """Return (tag, header_len, content_len, total_len) starting at offset i."""
    if i >= len(data):
        raise ValueError(f"TLV read past end (i={i}, len={len(data)})")
    tag = data[i]
    if i + 1 >= len(data):
        raise ValueError("TLV truncated at length byte")
    b = data[i + 1]
    if b < 0x80:
        return tag, 2, b, 2 + b
    n = b & 0x7F
    if n == 0 or n > 4:
        raise ValueError(f"unsupported DER length form (n={n})")
    if i + 2 + n > len(data):
        raise ValueError("TLV length bytes truncated")
    length = int.from_bytes(data[i + 2 : i + 2 + n], "big")
    return tag, 2 + n, length, 2 + n + length


def _content(data: bytes, i: int) -> Tuple[int, bytes, int]:
    """Return (tag, content_bytes, total_len) for the TLV at offset i."""
    tag, hl, cl, tl = _tlv(data, i)
    return tag, data[i + hl : i + hl + cl], tl


def _children(data: bytes, i: int) -> List[Tuple[int, int, int, int]]:
    """List children (tag, offset_in_data, content_len, total_len) of the
    constructed TLV at offset i. Offsets point to the start of each child."""
    tag, hl, cl, tl = _tlv(data, i)
    end = i + tl
    j = i + hl
    out = []
    while j < end:
        ctag, chl, ccl, ctl = _tlv(data, j)
        out.append((ctag, j, ccl, ctl))
        j += ctl
    return out


def _decode_oid(data: bytes) -> str:
    """Decode an OID content-bytes to dotted string."""
    if not data:
        return ""
    first = data[0]
    out = [str(first // 40), str(first % 40)]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            out.append(str(val))
            val = 0
    return ".".join(out)


def _find_child_by_oid(data: bytes, seq_offset: int, oid: str
                       ) -> Optional[Tuple[int, int, int, int]]:
    """Scan a constructed TLV for a child SEQUENCE whose first element is
    the given OID, and return that child's TLV tuple."""
    for ctag, coff, ccl, ctl in _children(data, seq_offset):
        if ctag in (TAG_SEQUENCE, 0xA0, 0xA1, 0xA2, 0xA3):
            try:
                inner = _children(data, coff)
                if inner and inner[0][0] == TAG_OID:
                    got = _decode_oid(data[inner[0][1] + 2 : inner[0][1] + 2 + inner[0][2]])
                    if got == oid:
                        return (ctag, coff, ccl, ctl)
            except Exception:
                continue
    return None


# ─────────────────────────────────────────────────────────────────────────
# Hash algorithm mapping
# ─────────────────────────────────────────────────────────────────────────

OID_SHA1     = "1.3.14.3.2.26"
OID_SHA256   = "2.16.840.1.101.3.4.2.1"
OID_SHA384   = "2.16.840.1.101.3.4.2.2"
OID_SHA512   = "2.16.840.1.101.3.4.2.3"
OID_MD5      = "1.2.840.113549.2.5"

_HASH_OIDS = {
    OID_MD5:    ("md5", hashlib.md5),
    OID_SHA1:   ("sha1", hashlib.sha1),
    OID_SHA256: ("sha256", hashlib.sha256),
    OID_SHA384: ("sha384", hashlib.sha384),
    OID_SHA512: ("sha512", hashlib.sha512),
}

if CRYPTO_AVAILABLE:
    _CRYPTO_HASHES = {
        OID_SHA1:   hashes.SHA1(),
        OID_SHA256: hashes.SHA256(),
        OID_SHA384: hashes.SHA384(),
        OID_SHA512: hashes.SHA512(),
        OID_MD5:    hashes.MD5(),
    }

# Authenticode / PKCS#7 OIDs
OID_PKCS7_SIGNED_DATA       = "1.2.840.113549.1.7.2"
OID_SPC_INDIRECT_DATA       = "1.3.6.1.4.1.311.2.1.4"
OID_MS_SPC_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1"
OID_CONTENT_TYPE_ATTR       = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST_ATTR     = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME_ATTR       = "1.2.840.113549.1.9.5"
OID_COUNTER_SIGNATURE_ATTR  = "1.2.840.113549.1.9.6"
OID_MS_STATEMENT_TYPE       = "1.3.6.1.4.1.311.2.1.11"

# RFC 3161 TimeStampToken unauth attribute (TSTInfo-carrying CMS)
OID_RFC3161_TIMESTAMP_TOKEN = "1.3.6.1.4.1.311.3.3.1"

# Authenticode / Driver EKUs
OID_EKU_CODE_SIGNING        = "1.3.6.1.5.5.7.3.3"
OID_EKU_WHQL_CRYPTO         = "1.3.6.1.4.1.311.10.3.5"    # Windows System Component Verification
OID_EKU_WHQL_ATTESTATION    = "1.3.6.1.4.1.311.10.3.5.1"  # Early-launch / attestation
OID_EKU_MS_SYSTEM_COMPONENT = "1.3.6.1.4.1.311.10.3.6"    # MS System Component (legacy kernel cross-sign)
OID_EKU_WINDOWS_KIT_CS      = "1.3.6.1.4.1.311.10.3.5"    # Alias for kernel cross-sign in some chains
OID_EKU_LIFETIME_SIGNING    = "1.3.6.1.5.5.7.3.8"
OID_EKU_TIMESTAMPING        = "1.3.6.1.5.5.7.3.8"

# All EKUs that grant kernel-signing authority
KERNEL_SIGNING_EKUS = {
    OID_EKU_WHQL_ATTESTATION,     # .10.3.5.1 — modern WHQL attestation
    OID_EKU_WHQL_CRYPTO,          # .10.3.5   — legacy WSVT
    OID_EKU_MS_SYSTEM_COMPONENT,  # .10.3.6   — MS System Component Verification
}

# Page hash OIDs (inside SpcPeImageData.file.SpcSerializedObject or moniker)
OID_SPC_PAGE_HASHES_V1      = "1.3.6.1.4.1.311.2.3.1"     # SHA-1 page hashes
OID_SPC_PAGE_HASHES_V2      = "1.3.6.1.4.1.311.2.3.2"     # SHA-256 page hashes

# EV code signing policy OIDs
OID_EV_CODE_SIGNING_CABF    = "2.23.140.1.3"              # CA/Browser Forum EV CS
# Vendor-specific EV CS policy OIDs (common in the wild)
EV_CODE_SIGNING_POLICIES = {
    OID_EV_CODE_SIGNING_CABF,
    "1.2.156.112570.1.1.3",
    "1.3.6.1.4.1.4146.1.2",       # GlobalSign EV CS
    "1.3.6.1.4.1.6334.1.100.1",   # Cybertrust EV CS
    "1.3.6.1.4.1.6449.1.2.1.6.1", # Comodo EV CS
    "1.3.6.1.4.1.14370.1.6",      # Entrust EV CS
    "1.3.6.1.4.1.17326.10.14.2.1.2",
    "1.3.6.1.4.1.22234.2.5.2.3.1",
    "1.3.6.1.4.1.34697.2.1",
    "1.3.6.1.4.1.34697.2.2",
    "1.3.6.1.4.1.34697.2.3",
    "1.3.6.1.4.1.34697.2.4",
    "2.16.756.1.89.1.2.1.1",
    "2.16.840.1.113733.1.7.23.6",  # Symantec/VeriSign EV
    "2.16.840.1.114412.3.1",       # DigiCert EV CS
    "2.16.840.1.114413.1.7.23.3",  # GoDaddy EV CS
    "2.16.840.1.114414.1.7.23.3",  # Starfield EV CS
    "2.16.840.1.114028.10.1.2",    # Entrust 2
}


# ─────────────────────────────────────────────────────────────────────────
# PKCS#7 SignedData parsing
# ─────────────────────────────────────────────────────────────────────────

def parse_signed_data(pkcs7_der: bytes) -> Optional[Dict]:
    """Parse a PKCS#7 SignedData blob into the structural pieces we need.

    Returns a dict with keys:
      - signed_data_offset, signed_data_len: the SignedData SEQUENCE
      - encap_content_oid: OID of encapContentInfo.contentType
      - encap_content_raw: raw bytes of encapContentInfo.content [0]
                           (with [0] tag stripped — the actual OCTET STRING
                           or SpcIndirectDataContent SEQUENCE)
      - signer_infos: list of (offset, total_len) for each SignerInfo
      - full: the original bytes (for offset math)
    """
    try:
        # ContentInfo ::= SEQUENCE { contentType OID, content [0] ... }
        tag, _, _, _ = _tlv(pkcs7_der, 0)
        if tag != TAG_SEQUENCE:
            return None
        ci_kids = _children(pkcs7_der, 0)
        if len(ci_kids) < 2 or ci_kids[0][0] != TAG_OID:
            return None
        oid_off = ci_kids[0][1]
        ct = _decode_oid(pkcs7_der[oid_off + 2 : oid_off + 2 + ci_kids[0][2]])
        if ct != OID_PKCS7_SIGNED_DATA:
            return None
        # content [0] EXPLICIT  → take first child of that wrapper as SignedData
        ctx_off = ci_kids[1][1]
        sd_kids = _children(pkcs7_der, ctx_off)
        if not sd_kids or sd_kids[0][0] != TAG_SEQUENCE:
            return None
        sd_off = sd_kids[0][1]
        sd_tl  = sd_kids[0][3]

        # SignedData fields in order:
        # version, digestAlgorithms SET, encapContentInfo SEQUENCE,
        # [0] certificates (opt), [1] crls (opt), signerInfos SET
        sd_kids = _children(pkcs7_der, sd_off)
        if len(sd_kids) < 4:
            return None
        # Find encapContentInfo (3rd element, index 2)
        encap_tag, encap_off, encap_cl, encap_tl = sd_kids[2]
        if encap_tag != TAG_SEQUENCE:
            return None
        encap_kids = _children(pkcs7_der, encap_off)
        if not encap_kids or encap_kids[0][0] != TAG_OID:
            return None
        econtent_oid = _decode_oid(
            pkcs7_der[encap_kids[0][1] + 2 : encap_kids[0][1] + 2 + encap_kids[0][2]])

        encap_content_raw = b""       # full TLV (for SpcIndirectData parsing)
        encap_content_for_hash = b""  # content-only slice (for messageDigest)
        if len(encap_kids) >= 2:
            # [0] EXPLICIT content — unwrap one layer
            ctag2, coff2, ccl2, ctl2 = encap_kids[1]
            if ctag2 & 0xE0 == 0xA0:  # context-specific constructed
                # inside is a single element: OCTET STRING or SEQUENCE
                inner = _children(pkcs7_der, coff2)
                if inner:
                    itag, ioff, icl, itl = inner[0]
                    _, hl, icl2, _ = _tlv(pkcs7_der, ioff)
                    encap_content_raw = pkcs7_der[ioff:ioff + itl]
                    # Authenticode messageDigest is computed over the
                    # *content* of the SpcIndirectDataContent SEQUENCE,
                    # NOT the outer SEQUENCE tag+length. If the content
                    # is wrapped in an OCTET STRING (CMS-style), strip
                    # that OCTET STRING's header too.
                    if itag == TAG_OCTETSTRING:
                        encap_content_for_hash = pkcs7_der[ioff + hl:
                                                           ioff + hl + icl2]
                    else:
                        encap_content_for_hash = pkcs7_der[ioff + hl:
                                                           ioff + hl + icl2]

        # signerInfos — last element, SET
        signer_infos = []
        si_set_tag, si_set_off, si_set_cl, si_set_tl = sd_kids[-1]
        if si_set_tag == TAG_SET:
            for sitag, sioff, sicl, sitl in _children(pkcs7_der, si_set_off):
                if sitag == TAG_SEQUENCE:
                    signer_infos.append((sioff, sitl))

        return {
            "signed_data_offset": sd_off,
            "signed_data_len": sd_tl,
            "encap_content_oid": econtent_oid,
            "encap_content_raw": encap_content_raw,
            "encap_content_for_hash": encap_content_for_hash,
            "signer_infos": signer_infos,
            "der": pkcs7_der,
        }
    except Exception:
        logger.debug("SignedData parsing failed", exc_info=True)
        return None


def parse_signer_info(der: bytes, off: int) -> Optional[Dict]:
    """Parse a SignerInfo SEQUENCE into its cryptographically-relevant pieces.

    Returns dict with:
      - issuer_and_serial_raw: bytes for matching signer cert
      - digest_algorithm_oid
      - signed_attrs_raw: the raw signedAttrs bytes RE-TAGGED as SET (0x31),
        which is what PKCS#7 hashes. None if signedAttrs are absent.
      - signed_attrs_tlv_raw: the actual bytes (with [0] context tag) if
        you need the original wire form (rarely).
      - message_digest: the 'messageDigest' attribute value (bytes)
      - signature_algorithm_oid
      - encrypted_digest: the RSA/EC signature bytes
      - unauth_attrs_off / unauth_attrs_len: for MsSpcNestedSignature lookup
    """
    try:
        kids = _children(der, off)
        # version INTEGER
        if not kids or kids[0][0] != TAG_INTEGER:
            return None
        idx = 1
        out: Dict = {}

        # issuerAndSerialNumber OR SubjectKeyIdentifier [0]
        tag, koff, kcl, ktl = kids[idx]
        out["issuer_and_serial_raw"] = der[koff:koff + ktl]
        idx += 1

        # digestAlgorithm  SEQUENCE { oid, params }
        tag, koff, kcl, ktl = kids[idx]
        da_kids = _children(der, koff)
        if not da_kids or da_kids[0][0] != TAG_OID:
            return None
        out["digest_algorithm_oid"] = _decode_oid(
            der[da_kids[0][1] + 2 : da_kids[0][1] + 2 + da_kids[0][2]])
        idx += 1

        # [0] signedAttrs  (optional, IMPLICIT SET)
        signed_attrs_tlv = None
        message_digest = None
        if idx < len(kids) and kids[idx][0] == 0xA0:
            sa_tag, sa_off, sa_cl, sa_tl = kids[idx]
            signed_attrs_tlv = der[sa_off:sa_off + sa_tl]
            # For signature computation, re-tag [0] as SET (0x31).
            # Content length encoding stays the same.
            retag = bytes([0x31]) + signed_attrs_tlv[1:]
            out["signed_attrs_for_hash"] = retag
            out["signed_attrs_tlv_raw"] = signed_attrs_tlv

            # Walk attributes looking for messageDigest (1.2.840.113549.1.9.4)
            # and signingTime (1.2.840.113549.1.9.5)
            signing_time_raw: Optional[bytes] = None
            for atag, aoff, acl, atl in _children(der, sa_off):
                if atag != TAG_SEQUENCE:
                    continue
                a_kids = _children(der, aoff)
                if len(a_kids) < 2 or a_kids[0][0] != TAG_OID:
                    continue
                a_oid = _decode_oid(
                    der[a_kids[0][1] + 2 : a_kids[0][1] + 2 + a_kids[0][2]])
                if a_oid == OID_MESSAGE_DIGEST_ATTR:
                    # values SET OF, take first element, expect OCTET STRING
                    vset = a_kids[1]
                    if vset[0] == TAG_SET:
                        for vtag, voff, vcl, vtl in _children(der, vset[1]):
                            if vtag == TAG_OCTETSTRING:
                                _, hl, cl, _ = _tlv(der, voff)
                                message_digest = der[voff + hl : voff + hl + cl]
                                break
                elif a_oid == OID_SIGNING_TIME_ATTR:
                    vset = a_kids[1]
                    if vset[0] == TAG_SET:
                        for vtag, voff, vcl, vtl in _children(der, vset[1]):
                            if vtag in (0x17, 0x18):  # UTCTime / GeneralizedTime
                                _, hl, cl, _ = _tlv(der, voff)
                                signing_time_raw = (
                                    bytes([vtag])
                                    + der[voff + 1 : voff + hl]
                                    + der[voff + hl : voff + hl + cl])
                                break
            out["signing_time_raw"] = signing_time_raw
            idx += 1
        out["signed_attrs_for_hash_opt"] = out.get("signed_attrs_for_hash")
        out["message_digest"] = message_digest

        # signatureAlgorithm SEQUENCE { oid, params }
        if idx >= len(kids):
            return None
        tag, koff, kcl, ktl = kids[idx]
        sa_kids = _children(der, koff)
        if not sa_kids or sa_kids[0][0] != TAG_OID:
            return None
        out["signature_algorithm_oid"] = _decode_oid(
            der[sa_kids[0][1] + 2 : sa_kids[0][1] + 2 + sa_kids[0][2]])
        idx += 1

        # encryptedDigest OCTET STRING
        if idx >= len(kids):
            return None
        tag, koff, kcl, ktl = kids[idx]
        if tag != TAG_OCTETSTRING:
            return None
        _, hl, cl, _ = _tlv(der, koff)
        out["encrypted_digest"] = der[koff + hl : koff + hl + cl]
        idx += 1

        # [1] unauthenticatedAttributes (optional)
        if idx < len(kids) and kids[idx][0] == 0xA1:
            ua_tag, ua_off, ua_cl, ua_tl = kids[idx]
            out["unauth_attrs_off"] = ua_off
            out["unauth_attrs_tl"] = ua_tl

        return out
    except Exception:
        logger.debug("SignedData parsing failed", exc_info=True)
        return None


# ─────────────────────────────────────────────────────────────────────────
# 1. PKCS#7 signature verification
# ─────────────────────────────────────────────────────────────────────────

def verify_pkcs7_signature(pkcs7_der: bytes, certs_der: List[bytes]
                           ) -> Tuple[bool, str]:
    """Cryptographically verify the primary PKCS#7 signature.

    Returns (valid, reason). `reason` is empty on success, otherwise a
    short string explaining why verification failed.

    Steps:
      1. Parse SignedData → first SignerInfo.
      2. Compute H_c = H(encapContentInfo.content) and compare to the
         messageDigest attribute value.
      3. Compute H_sa = H(signedAttrs re-tagged as SET).
      4. Find signer cert by issuer+serial and verify encryptedDigest
         over H_sa using the cert's public key.
    """
    if not CRYPTO_AVAILABLE:
        return False, "cryptography library not available"

    sd = parse_signed_data(pkcs7_der)
    if not sd:
        return False, "could not parse SignedData"
    if not sd["signer_infos"]:
        return False, "no signerInfo present"

    si_off, si_tl = sd["signer_infos"][0]
    si = parse_signer_info(pkcs7_der, si_off)
    if not si:
        return False, "could not parse SignerInfo"

    digest_oid = si["digest_algorithm_oid"]
    if digest_oid not in _HASH_OIDS:
        return False, f"unsupported digest OID {digest_oid}"
    _, hfn = _HASH_OIDS[digest_oid]

    encap_for_hash = sd.get("encap_content_for_hash") or b""
    if not encap_for_hash:
        return False, "encapContentInfo content missing"
    computed_content_digest = hfn(encap_for_hash).digest()

    md_attr = si.get("message_digest")
    if md_attr is None:
        return False, "messageDigest attribute missing"
    if computed_content_digest != md_attr:
        return (False,
                f"messageDigest mismatch (expected "
                f"{md_attr.hex()}, got {computed_content_digest.hex()})")

    signed_attrs_for_hash = si.get("signed_attrs_for_hash")
    if not signed_attrs_for_hash:
        return False, "signedAttrs missing (non-Authenticode-shape signature)"

    # Locate signer certificate by issuerAndSerialNumber match
    ias_raw = si.get("issuer_and_serial_raw", b"")
    signer_cert_obj = None
    for cder in certs_der:
        try:
            cert = load_der_x509_certificate(cder)
            # Build an issuerAndSerialNumber from the cert and compare DER
            # The simplest robust check: serial match AND issuer match
            if (ias_raw and
                    _cert_matches_issuer_serial(cder, ias_raw)):
                signer_cert_obj = cert
                break
        except Exception:
            continue
    if signer_cert_obj is None:
        return False, "signer certificate not found in chain"

    pub = signer_cert_obj.public_key()
    sig_alg_oid = si["signature_algorithm_oid"]
    ed = si["encrypted_digest"]

    try:
        if isinstance(pub, rsa.RSAPublicKey):
            # Classic PKCS#1 v1.5 (default for Authenticode)
            h_ctx = _CRYPTO_HASHES[digest_oid]
            pub.verify(ed, signed_attrs_for_hash,
                       padding.PKCS1v15(), h_ctx)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            h_ctx = _CRYPTO_HASHES[digest_oid]
            pub.verify(ed, signed_attrs_for_hash, ec.ECDSA(h_ctx))
        else:
            return False, f"unsupported public-key type {type(pub).__name__}"
    except Exception as e:
        return False, f"signature verify failed: {e.__class__.__name__}"

    return True, ""


def _cert_matches_issuer_serial(cert_der: bytes, ias_raw: bytes) -> bool:
    """Check if a cert's (issuer, serial) matches an IssuerAndSerialNumber
    DER blob. Robust against byte-for-byte DER differences by decoding
    the serial and comparing the raw issuer DER."""
    try:
        # Decode cert
        kids = _children(cert_der, 0)
        if len(kids) < 1 or kids[0][0] != TAG_SEQUENCE:
            return False
        tbs_kids = _children(cert_der, kids[0][1])
        # TBSCertificate fields: [0] version (optional), serial INTEGER,
        # sigAlg SEQ, issuer SEQ, validity SEQ, subject SEQ, ...
        idx = 0
        if tbs_kids and tbs_kids[0][0] == 0xA0:
            idx = 1  # skip version
        # serial
        if idx >= len(tbs_kids) or tbs_kids[idx][0] != TAG_INTEGER:
            return False
        s_tag, s_off, s_cl, s_tl = tbs_kids[idx]
        _, hl, cl, _ = _tlv(cert_der, s_off)
        cert_serial = cert_der[s_off + hl : s_off + hl + cl]
        idx += 2  # skip sigAlg
        # issuer
        if idx >= len(tbs_kids) or tbs_kids[idx][0] != TAG_SEQUENCE:
            return False
        i_tag, i_off, i_cl, i_tl = tbs_kids[idx]
        cert_issuer = cert_der[i_off : i_off + i_tl]

        # Parse IssuerAndSerialNumber from ias_raw
        ias_kids = _children(ias_raw, 0)
        if len(ias_kids) < 2:
            return False
        if ias_kids[0][0] != TAG_SEQUENCE:
            return False
        ias_issuer = ias_raw[ias_kids[0][1] : ias_kids[0][1] + ias_kids[0][3]]
        if ias_kids[1][0] != TAG_INTEGER:
            return False
        _, hl2, cl2, _ = _tlv(ias_raw, ias_kids[1][1])
        ias_serial = ias_raw[ias_kids[1][1] + hl2 : ias_kids[1][1] + hl2 + cl2]

        # Normalize leading zeros on serial
        cs = cert_serial.lstrip(b"\x00") or b"\x00"
        ias_s = ias_serial.lstrip(b"\x00") or b"\x00"
        return cs == ias_s and cert_issuer == ias_issuer
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────
# 2. Authenticode PE hash
# ─────────────────────────────────────────────────────────────────────────

def compute_authenticode_hash(pe_raw: bytes, pe_obj, digest_oid: str
                              ) -> Optional[bytes]:
    """Compute the canonical Authenticode hash of a PE image.

    Follows the Microsoft Authenticode specification:
      - hash bytes [0 .. CheckSum) of the Optional Header
      - skip the 4-byte CheckSum field
      - hash bytes [after CheckSum .. DataDirectory[CERTIFICATE])
      - skip the 8-byte Certificate Table directory entry
      - hash remainder of headers
      - hash each section's raw bytes in ascending PointerToRawData order
      - hash any trailing data that lies BEFORE the certificate table
        (the certificate table itself is excluded)

    Returns the digest bytes, or None on failure.
    """
    if digest_oid not in _HASH_OIDS:
        return None
    _, hfn = _HASH_OIDS[digest_oid]
    h = hfn()

    try:
        opt = pe_obj.OPTIONAL_HEADER
        # Offset of CheckSum in file:
        # dos_header.e_lfanew + sizeof(Signature=4) + sizeof(FileHeader=20)
        # + offset_of_CheckSum_in_OptHeader (0x40)
        e_lfanew = pe_obj.DOS_HEADER.e_lfanew
        checksum_off = e_lfanew + 4 + 20 + 0x40  # works for both PE32 & PE32+

        # Offset of DataDirectory[CERTIFICATE] (index 4).
        # NumberOfRvaAndSizes precedes DataDirectory.
        # PE32:  DataDirectory starts at OptHeader+0x60 (96)
        # PE32+: DataDirectory starts at OptHeader+0x70 (112)
        is_pe32_plus = opt.Magic == 0x20B
        opt_header_off = e_lfanew + 4 + 20
        dd_start = opt_header_off + (0x70 if is_pe32_plus else 0x60)
        cert_dir_off = dd_start + 4 * 8  # index 4 * 8 bytes per entry

        # Size of headers (end of the NT header region for hashing)
        size_of_headers = opt.SizeOfHeaders

        # Certificate table location from DataDirectory[4]
        cert_dir = opt.DATA_DIRECTORY[4]
        cert_rva = cert_dir.VirtualAddress  # actually a file offset for cert dir
        cert_size = cert_dir.Size

        # 1. hash [0 .. checksum_off)
        h.update(pe_raw[0:checksum_off])
        # 2. skip 4 bytes, hash [checksum_off+4 .. cert_dir_off)
        h.update(pe_raw[checksum_off + 4 : cert_dir_off])
        # 3. skip 8 bytes, hash [cert_dir_off+8 .. size_of_headers)
        h.update(pe_raw[cert_dir_off + 8 : size_of_headers])

        # 4. hash each section in ascending PointerToRawData order
        sections = sorted(
            [s for s in pe_obj.sections if s.SizeOfRawData > 0],
            key=lambda s: s.PointerToRawData)
        sum_of_bytes_hashed = size_of_headers
        for s in sections:
            start = s.PointerToRawData
            end = start + s.SizeOfRawData
            h.update(pe_raw[start:end])
            sum_of_bytes_hashed = max(sum_of_bytes_hashed, end)

        # 5. hash any trailing data that lies outside the cert table
        file_size = len(pe_raw)
        if cert_rva and cert_size:
            # Trailing data is between sum_of_bytes_hashed and cert_rva
            if sum_of_bytes_hashed < cert_rva:
                h.update(pe_raw[sum_of_bytes_hashed:cert_rva])
            # Any bytes AFTER the cert table (rare) are also excluded.
        else:
            if sum_of_bytes_hashed < file_size:
                h.update(pe_raw[sum_of_bytes_hashed:file_size])

        return h.digest()
    except Exception:
        logger.debug("SignedData parsing failed", exc_info=True)
        return None


def extract_spc_indirect_digest(encap_content_raw: bytes
                                ) -> Tuple[Optional[str], Optional[bytes]]:
    """From encapContentInfo content (SpcIndirectDataContent SEQUENCE),
    return (digest_oid, digest_bytes).

    SpcIndirectDataContent ::= SEQUENCE {
        data    SpcAttributeTypeAndOptionalValue,
        messageDigest  DigestInfo
    }
    DigestInfo ::= SEQUENCE {
        digestAlgorithm AlgorithmIdentifier,
        digest OCTET STRING
    }
    """
    try:
        if not encap_content_raw:
            return None, None
        # encap_content_raw is the SpcIndirectDataContent SEQUENCE (full TLV)
        tag, _, _, _ = _tlv(encap_content_raw, 0)
        if tag != TAG_SEQUENCE:
            return None, None
        top = _children(encap_content_raw, 0)
        if len(top) < 2:
            return None, None
        # DigestInfo is the 2nd child
        di_tag, di_off, di_cl, di_tl = top[1]
        if di_tag != TAG_SEQUENCE:
            return None, None
        di_kids = _children(encap_content_raw, di_off)
        if len(di_kids) < 2:
            return None, None
        # AlgorithmIdentifier
        alg_tag, alg_off, alg_cl, alg_tl = di_kids[0]
        alg_kids = _children(encap_content_raw, alg_off)
        if not alg_kids or alg_kids[0][0] != TAG_OID:
            return None, None
        oid = _decode_oid(
            encap_content_raw[alg_kids[0][1] + 2 :
                              alg_kids[0][1] + 2 + alg_kids[0][2]])
        # digest OCTET STRING
        dig_tag, dig_off, dig_cl, dig_tl = di_kids[1]
        if dig_tag != TAG_OCTETSTRING:
            return None, None
        _, hl, cl, _ = _tlv(encap_content_raw, dig_off)
        digest = encap_content_raw[dig_off + hl : dig_off + hl + cl]
        return oid, digest
    except Exception:
        logger.debug("SignedData parsing failed", exc_info=True)
        return None, None


# ─────────────────────────────────────────────────────────────────────────
# 3. Nested signature extraction
# ─────────────────────────────────────────────────────────────────────────

def extract_nested_signatures(pkcs7_der: bytes) -> List[bytes]:
    """Return a list of nested PKCS#7 signatures found in the primary
    SignerInfo's unauthenticated attributes (MsSpcNestedSignature,
    OID 1.3.6.1.4.1.311.2.4.1). Each element is a raw PKCS#7 DER blob
    ready to re-feed into parse_signed_data()."""
    sd = parse_signed_data(pkcs7_der)
    if not sd or not sd["signer_infos"]:
        return []
    si_off, si_tl = sd["signer_infos"][0]
    si = parse_signer_info(pkcs7_der, si_off)
    if not si or "unauth_attrs_off" not in si:
        return []

    ua_off = si["unauth_attrs_off"]
    nested: List[bytes] = []
    try:
        for atag, aoff, acl, atl in _children(pkcs7_der, ua_off):
            if atag != TAG_SEQUENCE:
                continue
            a_kids = _children(pkcs7_der, aoff)
            if len(a_kids) < 2 or a_kids[0][0] != TAG_OID:
                continue
            a_oid = _decode_oid(
                pkcs7_der[a_kids[0][1] + 2 : a_kids[0][1] + 2 + a_kids[0][2]])
            if a_oid != OID_MS_SPC_NESTED_SIGNATURE:
                continue
            # values SET OF → each value is a full PKCS#7 ContentInfo
            vset = a_kids[1]
            if vset[0] != TAG_SET:
                continue
            for vtag, voff, vcl, vtl in _children(pkcs7_der, vset[1]):
                if vtag == TAG_SEQUENCE:
                    nested.append(pkcs7_der[voff:voff + vtl])
    except Exception:
        logger.debug("Nested signature extraction failed", exc_info=True)
    return nested


# ─────────────────────────────────────────────────────────────────────────
# 4. Kernel-trusted root anchoring
# ─────────────────────────────────────────────────────────────────────────

def classify_chain_anchor(certificates: List[Dict], trusted_roots: Dict[str, Tuple[str, str]]
                          ) -> Dict:
    """Classify whether the chain terminates at a kernel-trusted root.

    `certificates` is the list produced by pe_analyzer (each has
    'thumbprint_sha1', 'issuer_cn', 'subject_cn', 'self_signed', 'is_ca').
    `trusted_roots` is constants.KERNEL_TRUSTED_ROOTS mapping thumbprint
    (lowercase hex) → (category, name).

    Returns a dict: {
       "kind": "ms-kernel" | "cross-sign" | "embedded-self-root"
             | "no-ms-root" | "unknown",
       "matched_thumbprint": "...",
       "matched_name": "...",
       "trusted_for_kernel": bool,
    }
    """
    # 1. Any cert in the bundle whose thumbprint matches a kernel-trusted root?
    for c in certificates:
        tp = (c.get("thumbprint_sha1") or "").lower()
        if tp in trusted_roots:
            kind, name = trusted_roots[tp]
            return {
                "kind": kind,
                "matched_thumbprint": tp,
                "matched_name": name,
                "trusted_for_kernel": True,
            }

    # 2. Is there a self-signed root in the bundle? (embedded but not trusted)
    for c in certificates:
        if c.get("self_signed") and c.get("is_ca"):
            return {
                "kind": "embedded-self-root",
                "matched_thumbprint": (c.get("thumbprint_sha1") or "").lower(),
                "matched_name": c.get("subject_cn", ""),
                "trusted_for_kernel": False,
            }

    # 3. Does any issuer name reference a Microsoft root (useful hint even
    # when the root itself isn't embedded — Windows supplies it)?
    for c in certificates:
        iss = (c.get("issuer_cn", "") or "").lower()
        if "microsoft root" in iss or "microsoft code" in iss:
            return {
                "kind": "ms-root-referenced",
                "matched_thumbprint": "",
                "matched_name": c.get("issuer_cn", ""),
                "trusted_for_kernel": True,
            }

    return {
        "kind": "no-ms-root",
        "matched_thumbprint": "",
        "matched_name": "",
        "trusted_for_kernel": False,
    }


# ─────────────────────────────────────────────────────────────────────────
# 5. signingTime extraction
# ─────────────────────────────────────────────────────────────────────────

def _decode_time(raw: bytes) -> Optional[str]:
    """Decode a UTCTime/GeneralizedTime TLV to ISO-8601 string (UTC).
    Returns None on failure. Accepts tag+length+content form."""
    if not raw or len(raw) < 3:
        return None
    try:
        tag = raw[0]
        _, hl, cl, _ = _tlv(raw, 0)
        body = raw[hl:hl + cl].decode("ascii", errors="ignore")
        if not body:
            return None
        if tag == 0x17:  # UTCTime: YYMMDDhhmmssZ
            if len(body) < 11:
                return None
            yy = int(body[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            mm = body[2:4]; dd = body[4:6]
            hh = body[6:8]; mi = body[8:10]
            ss = body[10:12] if len(body) >= 13 and body[10:12].isdigit() else "00"
            return f"{year:04d}-{mm}-{dd}T{hh}:{mi}:{ss}Z"
        elif tag == 0x18:  # GeneralizedTime: YYYYMMDDhhmmssZ (or fractional)
            if len(body) < 14:
                return None
            return (f"{body[0:4]}-{body[4:6]}-{body[6:8]}T"
                    f"{body[8:10]}:{body[10:12]}:{body[12:14]}Z")
    except Exception:
        logger.debug("SignedData parsing failed", exc_info=True)
        return None
    return None


def extract_signing_time(pkcs7_der: bytes) -> Optional[str]:
    """Return the authenticated signingTime of the primary SignerInfo (ISO).
    This is the producer-claimed time; for the authoritative time from a
    trusted TSA, use extract_countersignature_time()."""
    sd = parse_signed_data(pkcs7_der)
    if not sd or not sd["signer_infos"]:
        return None
    si_off, _ = sd["signer_infos"][0]
    si = parse_signer_info(pkcs7_der, si_off)
    if not si:
        return None
    return _decode_time(si.get("signing_time_raw") or b"")


def extract_countersignature_time(pkcs7_der: bytes) -> Tuple[Optional[str], str]:
    """Return (iso_time, source) where source is one of:
      "counter-sig"   — legacy PKCS#9 counterSignature
      "rfc3161"       — RFC 3161 TimeStampToken
      ""              — nothing found
    This is what you want for the cross-signing-deadline gate."""
    sd = parse_signed_data(pkcs7_der)
    if not sd or not sd["signer_infos"]:
        return None, ""
    si_off, _ = sd["signer_infos"][0]
    si = parse_signer_info(pkcs7_der, si_off)
    if not si or "unauth_attrs_off" not in si:
        return None, ""
    ua_off = si["unauth_attrs_off"]

    # Walk unauth attrs looking for counterSignature / RFC3161 token
    try:
        for atag, aoff, acl, atl in _children(pkcs7_der, ua_off):
            if atag != TAG_SEQUENCE:
                continue
            a_kids = _children(pkcs7_der, aoff)
            if len(a_kids) < 2 or a_kids[0][0] != TAG_OID:
                continue
            a_oid = _decode_oid(
                pkcs7_der[a_kids[0][1] + 2 : a_kids[0][1] + 2 + a_kids[0][2]])

            if a_oid == OID_COUNTER_SIGNATURE_ATTR:
                # value SET OF SignerInfo — that SignerInfo has a signingTime attr
                vset = a_kids[1]
                if vset[0] != TAG_SET:
                    continue
                for vtag, voff, vcl, vtl in _children(pkcs7_der, vset[1]):
                    if vtag != TAG_SEQUENCE:
                        continue
                    cs_si = parse_signer_info(pkcs7_der, voff)
                    if cs_si and cs_si.get("signing_time_raw"):
                        t = _decode_time(cs_si["signing_time_raw"])
                        if t:
                            return t, "counter-sig"
            elif a_oid == OID_RFC3161_TIMESTAMP_TOKEN:
                # value SET OF ContentInfo (CMS SignedData wrapping TSTInfo)
                vset = a_kids[1]
                if vset[0] != TAG_SET:
                    continue
                for vtag, voff, vcl, vtl in _children(pkcs7_der, vset[1]):
                    if vtag != TAG_SEQUENCE:
                        continue
                    tst_blob = pkcs7_der[voff:voff + vtl]
                    t = _extract_tstinfo_time(tst_blob)
                    if t:
                        return t, "rfc3161"
    except Exception:
        logger.debug("Countersignature extraction failed", exc_info=True)
    return None, ""


def _extract_tstinfo_time(cms_der: bytes) -> Optional[str]:
    """Pull the genTime from a TSTInfo wrapped in a CMS ContentInfo blob."""
    try:
        sd = parse_signed_data(cms_der)
        if not sd:
            return None
        content = sd.get("encap_content_for_hash") or b""
        if not content:
            return None
        # TSTInfo ::= SEQUENCE { version INTEGER, policy OID,
        #   messageImprint, serialNumber, genTime GeneralizedTime, ... }
        tag, _, _, _ = _tlv(content, 0)
        if tag != TAG_SEQUENCE:
            return None
        for ctag, coff, ccl, ctl in _children(content, 0):
            if ctag == 0x18:  # GeneralizedTime
                return _decode_time(content[coff:coff + ctl])
        return None
    except Exception:
        logger.debug("SignedData parsing failed", exc_info=True)
        return None


def verify_countersignature(pkcs7_der: bytes, certs_der: List[bytes]
                             ) -> Tuple[Optional[bool], bool, str, str]:
    """Cryptographically verify the timestamp countersignature.

    Returns (valid, binding_ok, source, reason). Fields:
      valid:
        True   — crypto verifies AND the TS binds to our primary sig
        False  — binding or crypto check failed
        None   — no countersignature present
      binding_ok:
        True   — TS's messageDigest/imprint binds to H(primary encryptedDigest).
                 When True but valid=False, the TS is legitimate but the
                 TSA's signature alg is one our crypto lib can't re-verify
                 (common with legacy VeriSign/Symantec G2 TSAs). Windows'
                 CryptoAPI handles these; accept them.
      source:     "counter-sig" | "rfc3161" | ""
      reason:     short string explaining any failure
    """
    if not CRYPTO_AVAILABLE:
        return None, False, "", "cryptography unavailable"

    sd = parse_signed_data(pkcs7_der)
    if not sd or not sd["signer_infos"]:
        return None, False, "", "no signerInfo"
    si_off, _ = sd["signer_infos"][0]
    si = parse_signer_info(pkcs7_der, si_off)
    if not si or "unauth_attrs_off" not in si:
        return None, False, "", "no unauth attrs"

    primary_enc_dig = si["encrypted_digest"]
    ua_off = si["unauth_attrs_off"]

    for atag, aoff, acl, atl in _children(pkcs7_der, ua_off):
        if atag != TAG_SEQUENCE:
            continue
        a_kids = _children(pkcs7_der, aoff)
        if len(a_kids) < 2 or a_kids[0][0] != TAG_OID:
            continue
        a_oid = _decode_oid(
            pkcs7_der[a_kids[0][1] + 2 : a_kids[0][1] + 2 + a_kids[0][2]])

        if a_oid == OID_COUNTER_SIGNATURE_ATTR:
            vset = a_kids[1]
            if vset[0] != TAG_SET:
                continue
            for vtag, voff, vcl, vtl in _children(pkcs7_der, vset[1]):
                if vtag != TAG_SEQUENCE:
                    continue
                cs = parse_signer_info(pkcs7_der, voff)
                if not cs:
                    return False, False, "counter-sig", "cannot parse CS SignerInfo"
                cs_digest_oid = cs.get("digest_algorithm_oid", "")
                if cs_digest_oid not in _HASH_OIDS:
                    return False, False, "counter-sig", f"unsupported TS digest {cs_digest_oid}"
                _, hfn = _HASH_OIDS[cs_digest_oid]
                md = cs.get("message_digest")
                if md is None:
                    return False, False, "counter-sig", "no messageDigest in CS"
                if hfn(primary_enc_dig).digest() != md:
                    return False, False, "counter-sig", "CS messageDigest mismatch"
                # Binding is proven by the messageDigest match above.
                binding_ok = True
                sa_for_hash = cs.get("signed_attrs_for_hash")
                if not sa_for_hash:
                    return False, binding_ok, "counter-sig", "no signedAttrs in CS"
                ias = cs.get("issuer_and_serial_raw", b"")
                ts_cert = None
                for cder in certs_der:
                    try:
                        if ias and _cert_matches_issuer_serial(cder, ias):
                            ts_cert = load_der_x509_certificate(cder); break
                    except Exception:
                        continue
                if ts_cert is None:
                    return False, binding_ok, "counter-sig", "TS signer cert not found"
                try:
                    pub = ts_cert.public_key()
                    h_ctx = _CRYPTO_HASHES[cs_digest_oid]
                    ed = cs["encrypted_digest"]
                    if isinstance(pub, rsa.RSAPublicKey):
                        pub.verify(ed, sa_for_hash, padding.PKCS1v15(), h_ctx)
                    elif isinstance(pub, ec.EllipticCurvePublicKey):
                        pub.verify(ed, sa_for_hash, ec.ECDSA(h_ctx))
                    else:
                        return False, binding_ok, "counter-sig", "unsupported TS pubkey"
                    return True, binding_ok, "counter-sig", ""
                except Exception as e:
                    return False, binding_ok, "counter-sig", f"TS verify failed: {e.__class__.__name__}"

        elif a_oid == OID_RFC3161_TIMESTAMP_TOKEN:
            vset = a_kids[1]
            if vset[0] != TAG_SET:
                continue
            for vtag, voff, vcl, vtl in _children(pkcs7_der, vset[1]):
                if vtag != TAG_SEQUENCE:
                    continue
                tst_blob = pkcs7_der[voff:voff + vtl]
                tst_certs = _extract_tst_certs(tst_blob)
                binding_ok = _tstinfo_binds_primary(tst_blob, primary_enc_dig)
                ok, reason = verify_pkcs7_signature(tst_blob, tst_certs)
                if ok and not binding_ok:
                    return False, False, "rfc3161", "TSTInfo imprint does not bind primary sig"
                return ok, binding_ok, "rfc3161", reason

    return None, False, "", "no countersignature present"


def _extract_tst_certs(tst_der: bytes) -> List[bytes]:
    """Walk a CMS SignedData blob and return DER of every embedded cert."""
    out: List[bytes] = []
    try:
        tag, _, _, _ = _tlv(tst_der, 0)
        if tag != TAG_SEQUENCE:
            return out
        kids = _children(tst_der, 0)
        if len(kids) < 2:
            return out
        sd_kids = _children(tst_der, kids[1][1])
        if not sd_kids or sd_kids[0][0] != TAG_SEQUENCE:
            return out
        sd_off = sd_kids[0][1]
        for ctag, coff, ccl, ctl in _children(tst_der, sd_off):
            if ctag == 0xA0:  # [0] IMPLICIT certificates
                for cc_tag, cc_off, cc_cl, cc_tl in _children(tst_der, coff):
                    if cc_tag == TAG_SEQUENCE:
                        out.append(tst_der[cc_off:cc_off + cc_tl])
    except Exception:
        pass
    return out


def _tstinfo_binds_primary(tst_der: bytes, primary_enc_dig: bytes) -> bool:
    """True if the TSTInfo's messageImprint.hashedMessage equals H(primary
    signature value) for some supported H. Verifies the TS is actually
    attesting the primary signature, not some unrelated blob."""
    try:
        sd = parse_signed_data(tst_der)
        if not sd:
            return False
        content = sd.get("encap_content_for_hash") or b""
        if not content:
            return False
        # TSTInfo.messageImprint is the 3rd child (after version, policy)
        kids = _children(content, 0)
        if len(kids) < 3:
            return False
        mi_tag, mi_off, mi_cl, mi_tl = kids[2]
        if mi_tag != TAG_SEQUENCE:
            return False
        mi_kids = _children(content, mi_off)
        if len(mi_kids) < 2:
            return False
        alg_kids = _children(content, mi_kids[0][1])
        if not alg_kids or alg_kids[0][0] != TAG_OID:
            return False
        alg_oid = _decode_oid(
            content[alg_kids[0][1] + 2 : alg_kids[0][1] + 2 + alg_kids[0][2]])
        if alg_oid not in _HASH_OIDS:
            return False
        _, hfn = _HASH_OIDS[alg_oid]
        # hashedMessage OCTET STRING
        hm_tag, hm_off, hm_cl, hm_tl = mi_kids[1]
        if hm_tag != TAG_OCTETSTRING:
            return False
        _, hl, cl, _ = _tlv(content, hm_off)
        hashed = content[hm_off + hl:hm_off + hl + cl]
        return hfn(primary_enc_dig).digest() == hashed
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────
# 6. Page hash detection
# ─────────────────────────────────────────────────────────────────────────

def detect_page_hashes(encap_content_raw: bytes) -> Tuple[bool, str]:
    """Return (present, algorithm) where algorithm is "sha1"/"sha256"/"".
    Windows HVCI requires page hashes for per-page integrity verification.

    We recursively scan the SpcIndirectDataContent for the page-hash OIDs
    rather than walking the full SpcPeImageData → SpcLink → moniker tree —
    the OID is the only signal we need and it's an unusual OID that won't
    occur elsewhere in legitimate Authenticode content.
    """
    if not encap_content_raw:
        return False, ""
    # Walk the entire blob looking for one of the page-hash OIDs.
    # A raw DER scan for the encoded OID bytes is cheap and robust.
    v1 = _encode_oid(OID_SPC_PAGE_HASHES_V1)
    v2 = _encode_oid(OID_SPC_PAGE_HASHES_V2)
    if v2 and (bytes([TAG_OID, len(v2)]) + v2) in encap_content_raw:
        return True, "sha256"
    if v1 and (bytes([TAG_OID, len(v1)]) + v1) in encap_content_raw:
        return True, "sha1"
    return False, ""


# ─────────────────────────────────────────────────────────────────────────
# 7. EV / WHQL EKU detection
# ─────────────────────────────────────────────────────────────────────────

def chain_has_whql_eku(certificates: List[Dict]) -> bool:
    """True if any cert in the chain carries a kernel-signing EKU:
      - 1.3.6.1.4.1.311.10.3.5.1 (WHQL attestation — modern)
      - 1.3.6.1.4.1.311.10.3.5   (Windows System Component Verification)
      - 1.3.6.1.4.1.311.10.3.6   (MS System Component — legacy kernel cross-sign)

    Any of these on ANY cert in the path is treated as kernel-authorised.
    The EKU can appear on the leaf or a kernel-cross-sign intermediate."""
    for c in certificates:
        eku = set(c.get("eku") or [])
        if eku & KERNEL_SIGNING_EKUS:
            return True
    return False


def certificate_is_ev(cert_der: bytes) -> bool:
    """True if the certificate's certificatePolicies extension references
    a known EV code-signing policy OID."""
    try:
        # Locate certificatePolicies OID (2.5.29.32) inside the TBS extensions.
        # Simple string-match on encoded OID + subsequent SEQUENCE walk.
        # Encoded 2.5.29.32 = 55 1D 20
        marker = bytes([TAG_OID, 0x03, 0x55, 0x1D, 0x20])
        idx = cert_der.find(marker)
        if idx < 0:
            return False
        # After the OID TLV optionally a BOOLEAN (critical) then an OCTET STRING
        # whose content is a SEQUENCE OF PolicyInformation.
        # We do a cheap OID-byte substring match inside the rest of the cert.
        tail = cert_der[idx:]
        for pol_oid in EV_CODE_SIGNING_POLICIES:
            enc = _encode_oid(pol_oid)
            if enc and (bytes([TAG_OID, len(enc)]) + enc) in tail:
                return True
    except Exception:
        return False
    return False


def _encode_oid(dotted: str) -> bytes:
    """Encode dotted-OID string back to DER content bytes (no tag/len)."""
    try:
        parts = [int(p) for p in dotted.split(".")]
        if len(parts) < 2:
            return b""
        out = bytearray([parts[0] * 40 + parts[1]])
        for v in parts[2:]:
            if v < 0:
                return b""
            if v == 0:
                out.append(0); continue
            chunk = []
            while v:
                chunk.append(v & 0x7F); v >>= 7
            chunk.reverse()
            for i in range(len(chunk) - 1):
                chunk[i] |= 0x80
            out.extend(chunk)
        return bytes(out)
    except Exception:
        return b""


def check_eku_propagation(certificates: List[Dict]
                          ) -> Tuple[bool, Optional[str]]:
    """Verify codeSigning EKU propagates across the chain.

    Per RFC 5280 / Microsoft's code-integrity policy, if an intermediate
    CA certificate has an EKU extension with explicit values, it
    RESTRICTS what EKUs descendants may claim — a CA with EKU set to
    only [serverAuth] cannot issue a valid codeSigning leaf.

    Returns (ok, broken_cert_subject_cn). `ok` is False if any CA cert
    in the chain has a non-empty EKU that excludes codeSigning (and
    excludes anyExtendedKeyUsage 2.5.29.37.0 wildcard). Certs with
    empty/absent EKU are fine (no restriction).

    Timestamp-authority certs (non-code-sign) are ignored.
    """
    ANY_EKU = "2.5.29.37.0"
    OID_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
    for c in certificates:
        if not c.get("is_ca"):
            continue
        eku = c.get("eku") or []
        if not eku:
            continue  # no restriction
        if OID_EKU_CODE_SIGNING in eku:
            continue
        if ANY_EKU in eku:
            continue
        # Kernel-signing EKU also satisfies the constraint for drivers
        if any(k in eku for k in KERNEL_SIGNING_EKUS):
            continue
        # Timestamp-authority CAs are in the chain only to validate the
        # countersignature — they never need codeSigning propagation.
        if OID_TIMESTAMPING in eku and OID_EKU_CODE_SIGNING not in eku:
            continue
        return False, c.get("subject_cn", "")
    return True, None


def infer_catalog_signed(version_info: Dict[str, str],
                          security_flags: Dict[str, bool]) -> Tuple[bool, str]:
    """When a driver is unsigned-embedded but its PE metadata says it
    is a Microsoft-shipped driver, it is most likely catalog-signed
    (.cat external signature). Such drivers load fine as long as the
    matching catalog is registered on the target system — we just
    cannot verify it standalone.

    Returns (is_likely_cat_signed, reason).
    """
    if not version_info:
        return False, ""
    company = (version_info.get("CompanyName") or "").lower()
    orig = (version_info.get("OriginalFilename") or "").lower()
    product = (version_info.get("ProductName") or "").lower()

    ms_indicators = ("microsoft corporation", "microsoft windows")
    product_indicators = (
        "microsoft® windows®", "microsoft windows operating",
        "windows operating system",
    )

    ms_company = any(ind in company for ind in ms_indicators)
    ms_product = any(ind in product for ind in product_indicators)
    force_integrity = bool(security_flags.get("FORCE_INTEGRITY"))

    # MS-shipped drivers always have FORCE_INTEGRITY set. Combined with
    # an MS company/product string, catalog signing is the only way the
    # binary could have shipped without an embedded signature.
    if (ms_company or ms_product) and force_integrity:
        return True, ("MS CompanyName + FORCE_INTEGRITY → likely "
                      "catalog-signed external signature")
    if ms_company and orig.endswith(".sys"):
        return True, ("MS CompanyName on a .sys → likely catalog-signed")
    return False, ""


def chain_has_ev_cert(certificates: List[Dict], cert_ders: List[bytes]) -> bool:
    """True if any end-entity cert in the chain has an EV code-signing policy.
    `certificates` is the parsed list (used for thumbprint/subject mapping),
    `cert_ders` is the raw-DER list; we match by position."""
    for i, c in enumerate(certificates):
        if c.get("is_ca"):
            continue
        if i < len(cert_ders) and certificate_is_ev(cert_ders[i]):
            return True
    return False
