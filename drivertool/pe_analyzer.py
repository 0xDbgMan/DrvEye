from __future__ import annotations

import datetime
import hashlib
import re
import struct
import logging
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import capstone

logger = logging.getLogger(__name__)
import capstone.x86_const as x86c
import pefile

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    from cryptography.x509.oid import NameOID, ExtensionOID
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

if TYPE_CHECKING:
    from drivertool.disassembler import Disassembler


class PEAnalyzer:
    def __init__(self, filepath: str):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            self.raw = f.read()
        self.pe = pefile.PE(data=self.raw)
        self.is_64bit = False
        self.is_driver = False
        self.file_hash = ""
        self.imports: Dict[str, List[str]] = {}
        self.exports: List[str] = []
        self.sections: List[dict] = []
        self.iat_map: Dict[int, str] = {}  # IAT address -> function name
        self.device_names: List[str] = []
        self.inferred_names: List[str] = []  # synthesized pair mates (lower confidence)
        self.registry_refs: List[str] = []  # \Registry\...\Services\<svc>, value names, etc.
        # Minifilter ALPC port names (FltCreateCommunicationPort). These are
        # the user-mode entry points for minifilter drivers, distinct from
        # classic \Device\* objects.
        self.minifilter_ports: List[str] = []
        self.cert_info: Dict = {}  # Authenticode certificate details
        self._code_sections_cache: Optional[List[Tuple[int, bytes]]] = None

    def parse(self) -> dict:
        self.file_hash = hashlib.sha256(self.raw).hexdigest()
        self.file_hash_sha1 = hashlib.sha1(self.raw).hexdigest()
        self.is_64bit = self.pe.FILE_HEADER.Machine == 0x8664
        self.is_driver = getattr(self.pe.OPTIONAL_HEADER, "Subsystem", 0) == 1

        # Imports
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "unknown"
                funcs = []
                for imp in entry.imports:
                    name = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    funcs.append(name)
                    if imp.address:
                        self.iat_map[imp.address] = name
                self.imports[dll_name] = funcs

        # Exports
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8", errors="replace") if exp.name else f"ord_{exp.ordinal}"
                self.exports.append(name)

        # Sections
        for sec in self.pe.sections:
            name = sec.Name.decode("utf-8", errors="replace").rstrip("\x00")
            self.sections.append({
                "name": name,
                "virtual_address": sec.VirtualAddress,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": sec.get_entropy(),
                "characteristics": sec.Characteristics,
                "executable": bool(sec.Characteristics & 0x20000000),
                "writable": bool(sec.Characteristics & 0x80000000),
            })

        # Device name strings
        self.device_names   = self._find_device_names()
        self.version_info   = self._parse_version_info()
        self.imphash        = self._compute_imphash()
        self.security_flags = self._parse_security_features()
        self.cert_info      = self._parse_authenticode_cert()

        return {
            "filepath":          self.filepath,
            "sha256":            self.file_hash,
            "arch":              "x64" if self.is_64bit else "x86",
            "is_driver":         self.is_driver,
            "image_base":        self.pe.OPTIONAL_HEADER.ImageBase,
            "entry_point":       self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "num_imports":       sum(len(v) for v in self.imports.values()),
            "num_exports":       len(self.exports),
            "num_sections":      len(self.sections),
            "file_size":         len(self.raw),
            "version_info":      self.version_info,
            "imphash":           self.imphash,
            "security_features": self.security_flags,
            "certificate":       self.cert_info,
        }

    def _parse_version_info(self) -> Dict[str, str]:
        """Extract VS_VERSIONINFO string table entries."""
        info: Dict[str, str] = {}
        try:
            if not hasattr(self.pe, "FileInfo"):
                return info
            for fi_list in self.pe.FileInfo:
                for fi in fi_list:
                    if fi.Key == b"StringFileInfo":
                        for st in fi.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode("utf-8", errors="replace").strip()
                                val = v.decode("utf-8", errors="replace").strip()
                                info[key] = val
        except Exception:
            logger.debug("Version info parsing failed", exc_info=True)
        return info

    def _compute_imphash(self) -> str:
        """Compute import hash (MD5 of normalised dll.function pairs)."""
        try:
            if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
                return ""
            pairs = []
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace").lower()
                for ext in (".dll", ".sys", ".ocx"):
                    if dll.endswith(ext):
                        dll = dll[: -len(ext)]
                        break
                for imp in entry.imports:
                    func = (imp.name.decode("utf-8", errors="replace").lower()
                            if imp.name else f"ord{imp.ordinal}")
                    pairs.append(f"{dll}.{func}")
            return hashlib.md5(",".join(pairs).encode()).hexdigest()
        except Exception:
            logger.debug("Imp hash computation failed", exc_info=True)
            return ""

    def _parse_security_features(self) -> Dict[str, bool]:
        """Check PE DllCharacteristics and LoadConfig for security mitigations."""
        dc = getattr(self.pe.OPTIONAL_HEADER, "DllCharacteristics", 0)
        feats: Dict[str, bool] = {
            "HIGH_ENTROPY_VA": bool(dc & 0x0020),
            "DYNAMIC_BASE":    bool(dc & 0x0040),
            "FORCE_INTEGRITY": bool(dc & 0x0080),
            "NX_COMPAT":       bool(dc & 0x0100),
            "NO_SEH":          bool(dc & 0x0400),
            "GUARD_CF":        bool(dc & 0x4000),
            "GS_COOKIE":       False,
            "HVCI_COMPATIBLE": False,
        }
        # GS cookie via LoadConfig
        try:
            lc = self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            feats["GS_COOKIE"] = getattr(lc, "SecurityCookie", 0) != 0
        except Exception:
            feats["GS_COOKIE"] = "__security_cookie" in [
                f for funcs in self.imports.values() for f in funcs
            ]
        # HVCI: FORCE_INTEGRITY + no W+X sections
        has_wx = any(s["writable"] and s["executable"] for s in self.sections)
        feats["HVCI_COMPATIBLE"] = feats["FORCE_INTEGRITY"] and not has_wx
        return feats

    def _parse_authenticode_cert(self) -> Dict:
        """
        Extract Authenticode certificate from the PE security directory.
        Parses the PKCS#7 SignedData to get signer info, validity, chain, etc.
        """
        info: Dict = {"signed": False}

        # Step 1: Check IMAGE_DIRECTORY_ENTRY_SECURITY (index 4)
        try:
            sec_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # SECURITY
            if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
                # No embedded sig — might be catalog-signed. Run inference.
                try:
                    from drivertool import authenticode as _ac
                    is_cat, reason = _ac.infer_catalog_signed(
                        self.version_info or {},
                        self.security_flags or {})
                    info["likely_catalog_signed"] = is_cat
                    info["catalog_sign_reason"] = reason
                except Exception:
                    info["likely_catalog_signed"] = False
                return info
        except (IndexError, AttributeError):
            return info

        # The security directory points to a WIN_CERTIFICATE structure
        # at a raw file offset (NOT an RVA)
        offset = sec_dir.VirtualAddress
        size = sec_dir.Size

        if offset + size > len(self.raw):
            return info

        cert_data = self.raw[offset:offset + size]
        if len(cert_data) < 8:
            return info

        # WIN_CERTIFICATE header: DWORD dwLength, WORD wRevision, WORD wCertificateType
        dw_length = struct.unpack_from("<I", cert_data, 0)[0]
        w_revision = struct.unpack_from("<H", cert_data, 4)[0]
        w_cert_type = struct.unpack_from("<H", cert_data, 6)[0]

        info["signed"] = True
        info["win_cert_revision"] = f"0x{w_revision:04X}"
        info["win_cert_type"] = w_cert_type  # 2 = PKCS#7

        if w_cert_type != 2:
            # Not PKCS#7 — we can't parse further but it's still signed
            info["cert_format"] = "non-PKCS7"
            return info

        # Extract the PKCS#7 DER blob (after 8-byte WIN_CERTIFICATE header)
        pkcs7_der = cert_data[8:dw_length]
        if len(pkcs7_der) < 32:
            return info

        if not CRYPTO_AVAILABLE:
            info["parse_error"] = "cryptography library not installed"
            return info

        try:
            self._parse_pkcs7_certs(pkcs7_der, info)
        except Exception as e:
            logger.debug("PKCS#7 cert parsing failed", exc_info=True)
            info["parse_error"] = str(e)

        # Tier-1 load-verdict primitives (stored even on partial parse_error)
        try:
            self._authenticode_verify(pkcs7_der, info)
        except Exception as e:
            logger.debug("Authenticode verification failed", exc_info=True)
            info["verify_error"] = str(e)

        return info

    def _parse_pkcs7_certs(self, pkcs7_der: bytes, info: Dict):
        """Parse X.509 certificates from PKCS#7 SignedData DER blob."""
        from cryptography.hazmat.primitives.serialization import pkcs7 as pkcs7_mod
        from cryptography.x509 import load_der_x509_certificate

        # Try to load certificates from the PKCS#7 structure
        try:
            certs = pkcs7_mod.load_der_pkcs7_certificates(pkcs7_der)
        except Exception:
            # Fallback: scan DER for certificate sequences
            certs = self._extract_certs_from_der(pkcs7_der)

        if not certs:
            info["cert_count"] = 0
            return

        info["cert_count"] = len(certs)
        info["certificates"] = []

        signer_cert = None
        now = datetime.datetime.now(datetime.timezone.utc)

        for i, cert in enumerate(certs):
            cert_entry = {}

            # Subject
            try:
                subj = cert.subject
                cn_attrs = subj.get_attributes_for_oid(NameOID.COMMON_NAME)
                cert_entry["subject_cn"] = cn_attrs[0].value if cn_attrs else ""
                org_attrs = subj.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                cert_entry["subject_org"] = org_attrs[0].value if org_attrs else ""
            except Exception:
                cert_entry["subject_cn"] = ""
                cert_entry["subject_org"] = ""

            # Issuer
            try:
                iss = cert.issuer
                cn_attrs = iss.get_attributes_for_oid(NameOID.COMMON_NAME)
                cert_entry["issuer_cn"] = cn_attrs[0].value if cn_attrs else ""
                org_attrs = iss.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                cert_entry["issuer_org"] = org_attrs[0].value if org_attrs else ""
            except Exception:
                cert_entry["issuer_cn"] = ""
                cert_entry["issuer_org"] = ""

            # Serial number
            cert_entry["serial"] = format(cert.serial_number, "x")

            # Validity (compat: not_valid_before_utc added in cryptography>=42)
            try:
                nb = cert.not_valid_before_utc
                na = cert.not_valid_after_utc
            except AttributeError:
                nb = cert.not_valid_before.replace(
                    tzinfo=datetime.timezone.utc)
                na = cert.not_valid_after.replace(
                    tzinfo=datetime.timezone.utc)
            cert_entry["not_before"] = nb.isoformat()
            cert_entry["not_after"] = na.isoformat()
            cert_entry["expired"] = now > na
            cert_entry["not_yet_valid"] = now < nb

            # Self-signed check (subject == issuer)
            cert_entry["self_signed"] = (cert.subject == cert.issuer)

            # Key type and size
            try:
                pub_key = cert.public_key()
                if isinstance(pub_key, rsa.RSAPublicKey):
                    cert_entry["key_type"] = "RSA"
                    cert_entry["key_size"] = pub_key.key_size
                elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                    cert_entry["key_type"] = "EC"
                    cert_entry["key_size"] = pub_key.key_size
                else:
                    cert_entry["key_type"] = type(pub_key).__name__
                    cert_entry["key_size"] = 0
            except Exception:
                cert_entry["key_type"] = "unknown"
                cert_entry["key_size"] = 0

            # SHA-1 thumbprint (for matching)
            try:
                cert_entry["thumbprint_sha1"] = cert.fingerprint(
                    hashes.SHA1()).hex()
                cert_entry["thumbprint_sha256"] = cert.fingerprint(
                    hashes.SHA256()).hex()
            except Exception:
                pass

            # Code signing EKU check
            try:
                eku = cert.extensions.get_extension_for_oid(
                    ExtensionOID.EXTENDED_KEY_USAGE)
                eku_oids = [u.dotted_string for u in eku.value]
                cert_entry["eku"] = eku_oids
                # 1.3.6.1.5.5.7.3.3 = codeSigning
                cert_entry["has_code_signing_eku"] = "1.3.6.1.5.5.7.3.3" in eku_oids
            except Exception:
                cert_entry["eku"] = []
                cert_entry["has_code_signing_eku"] = False

            # Signature hash algorithm (SHA-1 vs SHA-256 etc.)
            try:
                sig_alg = cert.signature_hash_algorithm
                cert_entry["signature_hash_algorithm"] = sig_alg.name if sig_alg else "unknown"
            except Exception:
                cert_entry["signature_hash_algorithm"] = "unknown"

            # Basic Constraints — CA flag
            try:
                bc = cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS)
                cert_entry["is_ca"] = bc.value.ca
            except Exception:
                cert_entry["is_ca"] = False

            info["certificates"].append(cert_entry)

        # Find the actual code-signing cert (not the timestamp signer).
        # Priority: non-CA cert with codeSigning EKU > non-CA cert > first cert
        code_signing_certs = [c for c in info["certificates"]
                              if not c.get("is_ca") and c.get("has_code_signing_eku")]
        if code_signing_certs:
            signer_cert = code_signing_certs[0]
        else:
            non_ca = [c for c in info["certificates"] if not c.get("is_ca")]
            if non_ca:
                signer_cert = non_ca[-1]  # Last non-CA is often the end-entity

        # Also extract countersignature / timestamp info
        ts_certs = [c for c in info["certificates"]
                    if not c.get("is_ca") and not c.get("has_code_signing_eku")
                    and c != signer_cert]
        if ts_certs:
            ts = ts_certs[0]
            info["timestamp_signer"] = ts.get("subject_cn", "")
            info["timestamp_issuer"] = ts.get("issuer_cn", "")

        # Promote signer info to top level for easy access
        if signer_cert:
            info["signer_cn"] = signer_cert.get("subject_cn", "")
            info["signer_org"] = signer_cert.get("subject_org", "")
            info["signer_serial"] = signer_cert.get("serial", "")
            info["signer_issuer"] = signer_cert.get("issuer_cn", "")
            info["signer_expired"] = signer_cert.get("expired", False)
            info["signer_self_signed"] = signer_cert.get("self_signed", False)
            info["signer_key_type"] = signer_cert.get("key_type", "")
            info["signer_key_size"] = signer_cert.get("key_size", 0)
            info["signer_not_after"] = signer_cert.get("not_after", "")
            info["signer_thumbprint"] = signer_cert.get("thumbprint_sha1", "")
        elif info["certificates"]:
            # Fallback to first cert
            first = info["certificates"][0]
            info["signer_cn"] = first.get("subject_cn", "")
            info["signer_org"] = first.get("subject_org", "")
            info["signer_serial"] = first.get("serial", "")
            info["signer_issuer"] = first.get("issuer_cn", "")
            info["signer_expired"] = first.get("expired", False)
            info["signer_self_signed"] = first.get("self_signed", False)
            info["signer_key_type"] = first.get("key_type", "")
            info["signer_key_size"] = first.get("key_size", 0)
            info["signer_not_after"] = first.get("not_after", "")
            info["signer_thumbprint"] = first.get("thumbprint_sha1", "")

    def _authenticode_verify(self, pkcs7_der: bytes, info: Dict) -> None:
        """Tier-1 load-verdict primitives: PKCS#7 signature verify,
        Authenticode PE hash compare, nested-signature parse, and
        kernel-root chain anchoring.

        All results are written into `info` using consistent keys so
        scanner/certificate.py can render a correct load verdict even
        when a strictly signed-looking driver fails crypto validation.
        """
        from drivertool import authenticode as ac
        from drivertool.constants import KERNEL_TRUSTED_ROOTS

        # Pull DER of each parsed cert for signature verification + chain work
        certs_der: List[bytes] = self._extract_raw_cert_ders(pkcs7_der)

        # 1. Cryptographic PKCS#7 signature verification
        valid, reason = ac.verify_pkcs7_signature(pkcs7_der, certs_der)
        info["signature_valid"] = valid
        info["signature_error"] = reason

        # 2. Authenticode PE hash compare
        sd = ac.parse_signed_data(pkcs7_der)
        pe_hash_ok = None
        pe_hash_expected = b""
        pe_hash_actual = b""
        pe_hash_algo = ""
        if sd:
            spc_oid, spc_digest = ac.extract_spc_indirect_digest(
                sd["encap_content_raw"])
            if spc_digest and spc_oid:
                pe_hash_expected = spc_digest
                pe_hash_algo = ac._HASH_OIDS.get(spc_oid, ("?", None))[0]
                computed = ac.compute_authenticode_hash(
                    self.raw, self.pe, spc_oid)
                if computed is not None:
                    pe_hash_actual = computed
                    pe_hash_ok = (computed == spc_digest)
        info["pe_hash_match"] = pe_hash_ok  # True/False/None (None=couldn't compute)
        info["pe_hash_expected"] = pe_hash_expected.hex() if pe_hash_expected else ""
        info["pe_hash_actual"] = pe_hash_actual.hex() if pe_hash_actual else ""
        info["pe_hash_algorithm"] = pe_hash_algo

        # 3. Nested signatures (MsSpcNestedSignature)
        nested: List[Dict] = []
        for nested_der in ac.extract_nested_signatures(pkcs7_der):
            n_sd = ac.parse_signed_data(nested_der)
            if not n_sd or not n_sd["signer_infos"]:
                continue
            si_off, _ = n_sd["signer_infos"][0]
            si = ac.parse_signer_info(nested_der, si_off)
            if not si:
                continue
            n_entry = {
                "digest_algorithm_oid": si.get("digest_algorithm_oid", ""),
                "digest_algorithm": ac._HASH_OIDS.get(
                    si.get("digest_algorithm_oid", ""), ("?", None))[0],
            }
            # Verify the nested signature too
            nested_certs = self._extract_raw_cert_ders(nested_der)
            n_valid, n_reason = ac.verify_pkcs7_signature(nested_der, nested_certs)
            n_entry["signature_valid"] = n_valid
            n_entry["signature_error"] = n_reason
            # And its PE hash
            n_spc_oid, n_spc_digest = ac.extract_spc_indirect_digest(
                n_sd["encap_content_raw"])
            if n_spc_oid and n_spc_digest:
                n_entry["pe_hash_algorithm"] = ac._HASH_OIDS.get(
                    n_spc_oid, ("?", None))[0]
                n_computed = ac.compute_authenticode_hash(
                    self.raw, self.pe, n_spc_oid)
                if n_computed is not None:
                    n_entry["pe_hash_match"] = (n_computed == n_spc_digest)
                    n_entry["pe_hash_expected"] = n_spc_digest.hex()
                    n_entry["pe_hash_actual"] = n_computed.hex()
            nested.append(n_entry)
        info["nested_signatures"] = nested

        # 4. Chain anchoring (kernel trust roots)
        info["chain_anchor"] = ac.classify_chain_anchor(
            info.get("certificates", []), KERNEL_TRUSTED_ROOTS)

        # 5. signingTime (authenticated, producer-claimed)
        info["signing_time"] = ac.extract_signing_time(pkcs7_der)
        # Authoritative time from a trusted TSA countersignature
        ts_time, ts_source = ac.extract_countersignature_time(pkcs7_der)
        info["countersig_time"] = ts_time
        info["countersig_source"] = ts_source

        # 6. Timestamp countersignature cryptographic verification
        ts_valid, ts_binding_ok, ts_src, ts_reason = ac.verify_countersignature(
            pkcs7_der, certs_der)
        info["timestamp_valid"] = ts_valid  # True / False / None
        info["timestamp_binding_ok"] = ts_binding_ok
        info["timestamp_source"] = ts_src
        info["timestamp_error"] = ts_reason

        # 7. Page hashes (HVCI prerequisite)
        page_present = False
        page_alg = ""
        if sd:
            page_present, page_alg = ac.detect_page_hashes(
                sd["encap_content_raw"])
        if not page_present:
            # Check nested too — SHA-256 dual-sign commonly carries page hashes.
            for nested_der in ac.extract_nested_signatures(pkcs7_der):
                n_sd = ac.parse_signed_data(nested_der)
                if n_sd:
                    p, a = ac.detect_page_hashes(n_sd["encap_content_raw"])
                    if p:
                        page_present, page_alg = True, a
                        break
        info["page_hashes_present"] = page_present
        info["page_hashes_algorithm"] = page_alg

        # 8. WHQL attestation / kernel-signing EKU
        info["has_whql_eku"] = ac.chain_has_whql_eku(
            info.get("certificates", []))

        # 9. EV code-signing policy on end-entity
        info["has_ev_cert"] = ac.chain_has_ev_cert(
            info.get("certificates", []), certs_der)

        # 10. EKU propagation — intermediates must not exclude codeSigning
        eku_ok, eku_broken_cn = ac.check_eku_propagation(
            info.get("certificates", []))
        info["eku_propagation_ok"] = eku_ok
        info["eku_broken_cert_cn"] = eku_broken_cn or ""

    def _extract_raw_cert_ders(self, pkcs7_der: bytes) -> List[bytes]:
        """Return a list of raw DER cert blobs found inside a PKCS#7 blob.

        We walk the DER for the SignedData.certificates SET [0] and pick
        every SEQUENCE that parses as a valid X.509 certificate — more
        reliable than relying on cryptography.pkcs7.load_der_pkcs7_certificates
        alone and gives us byte-exact DER for signer matching.
        """
        from cryptography.x509 import load_der_x509_certificate
        out: List[bytes] = []
        i = 0
        n = len(pkcs7_der)
        while i < n - 4:
            if pkcs7_der[i] == 0x30 and pkcs7_der[i + 1] == 0x82:
                seq_len = struct.unpack_from(">H", pkcs7_der, i + 2)[0]
                total = seq_len + 4
                if i + total <= n:
                    blob = pkcs7_der[i:i + total]
                    try:
                        load_der_x509_certificate(blob)
                        out.append(blob)
                        i += total
                        continue
                    except Exception:
                        pass
            i += 1
        return out

    def _extract_certs_from_der(self, data: bytes) -> list:
        """Fallback: scan raw DER for X.509 certificate SEQUENCE headers."""
        from cryptography.x509 import load_der_x509_certificate
        certs = []
        i = 0
        while i < len(data) - 4:
            # ASN.1 SEQUENCE tag = 0x30, followed by length
            if data[i] == 0x30 and data[i + 1] == 0x82:
                seq_len = struct.unpack_from(">H", data, i + 2)[0]
                total = seq_len + 4
                if i + total <= len(data):
                    try:
                        cert = load_der_x509_certificate(data[i:i + total])
                        certs.append(cert)
                        i += total
                        continue
                    except Exception:
                        pass
            i += 1
        return certs

    def get_code_sections(self) -> List[Tuple[int, bytes]]:
        if self._code_sections_cache is not None:
            return self._code_sections_cache
        result = []
        for sec in self.pe.sections:
            if sec.Characteristics & 0x20000000:
                va = self.pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
                data = sec.get_data()
                result.append((va, data))
        self._code_sections_cache = result
        return result

    def get_entry_point_bytes(self, count: int = 512) -> Tuple[int, bytes]:
        ep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_va = self.pe.OPTIONAL_HEADER.ImageBase + ep_rva
        try:
            ep_offset = self.pe.get_offset_from_rva(ep_rva)
            data = self.raw[ep_offset:ep_offset + count]
            return (ep_va, data)
        except Exception:
            logger.debug("Entry point byte read failed", exc_info=True)
            return (ep_va, b"")

    def get_bytes_at_rva(self, rva: int, count: int) -> bytes:
        try:
            offset = self.pe.get_offset_from_rva(rva)
            return self.raw[offset:offset + count]
        except Exception:
            logger.debug("RVA byte read failed", exc_info=True)
            return b""

    def extract_pool_tags(self, dis: Disassembler) -> List[Tuple[int, str, str]]:
        """
        Extract pool tags from ExAllocatePoolWithTag calls.
        The tag is the 3rd argument (r8d in x64), typically loaded as a
        32-bit immediate:  mov r8d, 'Tag\x00'

        Returns [(call_va, tag_ascii, alloc_func), ...]
        """
        ALLOC_FUNCS = {"ExAllocatePoolWithTag", "ExAllocatePool2",
                       "ExAllocatePoolWithQuotaTag", "ExAllocatePoolZero"}
        image_base = self.pe.OPTIONAL_HEADER.ImageBase if hasattr(self.pe, 'OPTIONAL_HEADER') else self.pe.pe.OPTIONAL_HEADER.ImageBase
        results: List[Tuple[int, str, str]] = []

        for sec_va, sec_data in self.get_code_sections():
            insns = dis.disassemble_range(sec_data, sec_va)
            r8_val: Optional[int] = None
            for i, insn in enumerate(insns):
                # Track: mov r8d, imm32 (pool tag)
                if insn.mnemonic == "mov" and len(insn.operands) == 2:
                    dst, src = insn.operands
                    if (dst.type == x86c.X86_OP_REG and
                            dst.reg in (x86c.X86_REG_R8D, x86c.X86_REG_R8) and
                            src.type == x86c.X86_OP_IMM):
                        r8_val = src.imm & 0xFFFFFFFF

                if insn.mnemonic == "call" and insn.operands:
                    op = insn.operands[0]
                    call_target = None
                    if op.type == x86c.X86_OP_IMM:
                        call_target = op.imm
                    elif (op.type == x86c.X86_OP_MEM and
                            op.mem.base == x86c.X86_REG_RIP and
                            op.mem.index == 0):
                        call_target = insn.address + insn.size + op.mem.disp
                    if call_target and call_target in self.iat_map:
                        fn = self.iat_map[call_target]
                        if fn in ALLOC_FUNCS and r8_val is not None:
                            try:
                                tag = struct.pack("<I", r8_val).decode("ascii", errors="replace").rstrip("\x00")
                            except Exception:
                                tag = f"0x{r8_val:08X}"
                            results.append((insn.address, tag, fn))
                    # Reset r8 tracking after any call
                    r8_val = None

        return results

    def _find_device_names(self) -> List[str]:
        names = []
        seen = set()

        # -- ASCII scan (expanded character set: includes #{} for GUIDs/interfaces) --
        # Require at least 3 alphanumeric chars after the prefix to avoid noise
        ascii_patterns = [
            rb"\\Device\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\DosDevices\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\\?\?\\[A-Za-z][A-Za-z0-9_\-\.#\{\}]{2,}",
            rb"\\GLOBAL\?\?\\[A-Za-z][A-Za-z0-9_\-\.#\{\}]{2,}",
            rb"\\BaseNamedObjects\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\FileSystem\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\Callback\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\Driver\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\ObjectTypes\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\KernelObjects\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\RPC Control\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\Security\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\NLS\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\Sessions\\[0-9]+\\DosDevices\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\Sessions\\[0-9]+\\BaseNamedObjects\\[A-Za-z0-9_\-\.#\{\}]{3,}",
            rb"\\GLOBAL\?\?\\GLOBALROOT\\[A-Za-z0-9_\-\.#\{\}\\]{3,}",
        ]
        for pat in ascii_patterns:
            for m in re.finditer(pat, self.raw):
                s = m.group().decode("utf-8", errors="replace")
                if s not in seen:
                    seen.add(s)
                    names.append(s)

        # -- GUID-style device interface paths --
        # Pattern: \??\{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
        guid_pat = rb"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
        for m in re.finditer(guid_pat, self.raw):
            g = m.group().decode("ascii", errors="replace")
            if g not in seen:
                seen.add(g)
                names.append(f"DeviceInterface:{g}")

        # Also scan UTF-16LE for GUIDs
        guid_pat_wide = rb"\{\x00[0-9A-Fa-f]\x00[0-9A-Fa-f]\x00[0-9A-Fa-f]\x00[0-9A-Fa-f]\x00[0-9A-Fa-f]\x00[0-9A-Fa-f]\x00[0-9A-Fa-f]\x00[0-9A-Fa-f]\x00-\x00"
        for m in re.finditer(guid_pat_wide, self.raw):
            start = m.start()
            # Read enough for full GUID in UTF-16LE (~76 bytes)
            chunk = self.raw[start:start + 78]
            try:
                g = chunk.decode("utf-16-le").rstrip("\x00")
                if re.match(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}", g):
                    label = f"DeviceInterface:{g}"
                    if label not in seen:
                        seen.add(label)
                        names.append(label)
            except Exception:
                pass

        # -- UTF-16LE scan --
        def _w(s: str) -> bytes:
            return s.encode("utf-16-le")
        utf16_prefixes = [
            _w("\\Device\\"),
            _w("\\DosDevices\\"),
            _w("\\??\\"),
            _w("\\GLOBAL??\\"),
            _w("\\BaseNamedObjects\\"),
            _w("\\FileSystem\\"),
            _w("\\Callback\\"),
            _w("\\Driver\\"),
            _w("\\ObjectTypes\\"),
            _w("\\KernelObjects\\"),
            _w("\\RPC Control\\"),
            _w("\\Security\\"),
            _w("\\NLS\\"),
        ]
        raw = self.raw
        for prefix_bytes in utf16_prefixes:
            start = 0
            while True:
                idx = raw.find(prefix_bytes, start)
                if idx == -1:
                    break
                start = idx + 1
                end = idx + len(prefix_bytes)
                while end + 1 < len(raw):
                    ch = raw[end] | (raw[end + 1] << 8)
                    if ch == 0:
                        break
                    if ch < 0x20 or ch > 0x7E:
                        break
                    end += 2
                chunk = raw[idx:end]
                if len(chunk) < len(prefix_bytes) + 2:
                    continue
                try:
                    name = chunk.decode("utf-16-le").rstrip("\x00")
                    # Require the part after the prefix to be at least 3 chars
                    # and start with a letter (avoids binary noise matches)
                    prefix_decoded = prefix_bytes.decode("utf-16-le")
                    suffix_part = name[len(prefix_decoded):]
                    if (len(suffix_part) >= 3 and suffix_part[0].isalpha()
                            and name not in seen):
                        seen.add(name)
                        names.append(name)
                except Exception:
                    pass

        return names

    def _read_wide_str(self, va: int) -> Optional[str]:
        """Read a null-terminated UTF-16LE string from a virtual address."""
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        rva = va - image_base
        data = self.get_bytes_at_rva(rva, 512)
        end = 0
        while end + 1 < len(data):
            if data[end] == 0 and data[end + 1] == 0:
                break
            end += 2
        if end == 0:
            return None
        try:
            return data[:end].decode("utf-16-le")
        except Exception:
            return None

    def _read_unicode_string_struct(self, va: int) -> Optional[str]:
        """Read UNICODE_STRING {Length, MaxLength, Buffer*} from VA, return Buffer string."""
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        us = self.get_bytes_at_rva(va - image_base, 16)
        if len(us) < 16:
            return None
        buf_ptr = struct.unpack_from("<Q", us, 8)[0]
        if not buf_ptr:
            return None
        return self._read_wide_str(buf_ptr)

    def _read_guid_struct(self, va: int) -> Optional[str]:
        """Read a 16-byte GUID struct from VA, return {XXXXXXXX-XXXX-...} form."""
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        data = self.get_bytes_at_rva(va - image_base, 16)
        if len(data) < 16:
            return None
        try:
            d1, d2, d3 = struct.unpack_from("<IHH", data, 0)
            d4 = data[8:16]
        except Exception:
            return None
        # Reject obviously-bogus GUIDs: all-zero or all-0xFF
        if d1 == 0 and d2 == 0 and d3 == 0 and all(b == 0 for b in d4):
            return None
        if d1 == 0xFFFFFFFF and d2 == 0xFFFF and d3 == 0xFFFF and all(b == 0xFF for b in d4):
            return None
        return ("{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-"
                "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}").format(
                    d1, d2, d3, d4[0], d4[1],
                    d4[2], d4[3], d4[4], d4[5], d4[6], d4[7])

    def _find_name_wrapper_funcs(self, dis: "Disassembler",
                                  target_iat: set) -> set:
        """Discover intra-module helper functions that themselves call one
        of the name-registration APIs in ``target_iat``.

        When the driver wraps ``IoCreateDevice`` / ``RtlInitUnicodeString``
        in an internal ``MyCreateDevice(PCWSTR name)`` helper, the device
        name is loaded in the caller and passed by register — our tracers
        miss it because the call target is the helper, not an IAT entry.
        Adding the helper VAs to the ``interesting`` / ``target_iat`` set
        lets the tracers apply at those call sites too, so they can catch
        the caller-side ``lea`` / stack-packed / XMM-spilled name.
        """
        if not target_iat:
            return set()
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        wrappers: set = set()

        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=30000)

            # Split into function windows
            starts = [0]
            for j, insn in enumerate(insns):
                if insn.mnemonic in ("ret", "retf"):
                    starts.append(j + 1)
                elif (insn.mnemonic == "int3" and j + 1 < len(insns) and
                      insns[j + 1].mnemonic == "int3"):
                    starts.append(j + 1)

            for a, b in zip(starts, starts[1:] + [len(insns)]):
                if a >= len(insns):
                    continue
                window = insns[a:b]
                if len(window) < 3 or len(window) > 1500:
                    continue
                func_va = window[0].address

                for insn in window:
                    if insn.mnemonic != "call" or not insn.operands:
                        continue
                    op = insn.operands[0]
                    tgt: Optional[int] = None
                    if op.type == x86c.X86_OP_IMM:
                        tgt = op.imm
                    elif (op.type == x86c.X86_OP_MEM and
                          op.mem.base == x86c.X86_REG_RIP and
                          op.mem.index == 0):
                        tgt = insn.address + insn.size + op.mem.disp
                    if tgt in target_iat:
                        wrappers.add(func_va)
                        break

        # Drop wrappers that ARE the IAT targets themselves (impossible
        # here — IAT targets live in .idata, not executable sections —
        # but belt-and-braces against future refactors).
        wrappers -= target_iat
        return wrappers

    def trace_device_names_disasm(self, iat_map: Dict[int, str],
                                   dis: Disassembler) -> List[str]:
        """
        Scan ALL code sections for calls to RtlInitUnicodeString /
        IoCreateDevice / IoCreateSymbolicLink and extract the string
        arguments using a lightweight register tracker.

        x64 calling convention:
          RtlInitUnicodeString(PUNICODE_STRING us, PCWSTR src)
            rdx = src  <- raw wide-char string literal (easiest to extract)

          IoCreateSymbolicLink(PUNICODE_STRING link, PUNICODE_STRING target)
            rcx = &link  <- UNICODE_STRING already initialised; .Buffer has string

        Strategy: for each function, disassemble a window of up to 200
        instructions ending at the CALL, tracking 'lea reg, [rip+X]'.
        """
        image_base = self.pe.OPTIONAL_HEADER.ImageBase

        # IAT addr -> function name for functions we care about
        interesting: Dict[int, str] = {}
        for addr, name in iat_map.items():
            if name in ("RtlInitUnicodeString", "RtlUnicodeStringInit",
                        "IoCreateDevice", "IoCreateSymbolicLink",
                        "IoCreateUnprotectedSymbolicLink",
                        "IoDeleteSymbolicLink",
                        "IoCreateDeviceSecure", "WdmlibIoCreateDeviceSecure",
                        "IoRegisterDeviceInterface",
                        "WdfDeviceCreateSymbolicLink",
                        "WdfDeviceCreateDeviceInterface",
                        "ZwCreateSymbolicLinkObject",
                        "ObReferenceObjectByName"):
                interesting[addr] = name
        if not interesting:
            return []

        # 1-level interprocedural: intra-module helpers that themselves call
        # one of the APIs above. We treat them as synthetic wrappers and try
        # all arg registers at their call sites.
        wrapper_vas = self._find_name_wrapper_funcs(dis, set(interesting.keys()))
        for va in wrapper_vas:
            interesting[va] = "__name_wrapper"

        found: List[str] = []
        seen_strings: set = set()

        DEVICE_PREFIXES = ("\\Device\\", "\\DosDevices\\",
                           "\\??\\", "\\GLOBAL??\\")
        VOLATILE = (x86c.X86_REG_RCX, x86c.X86_REG_RDX, x86c.X86_REG_R8,
                    x86c.X86_REG_R9, x86c.X86_REG_RAX, x86c.X86_REG_R10,
                    x86c.X86_REG_R11)

        def _is_device_str(s: Optional[str]) -> bool:
            return bool(s and len(s) > 4 and
                        any(s.startswith(p) for p in DEVICE_PREFIXES))

        def _try_extract(insns: list, call_idx: int, func: str):
            """
            Walk backwards from call_idx tracking LEA reg,[rip+X].
            Stop (reset reg) whenever any CALL instruction is seen --
            that clobbers all volatile registers.
            """
            regs: Dict[int, int] = {}
            for insn in reversed(insns[max(0, call_idx - 40): call_idx]):
                # Any call in between clobbers volatile regs
                if insn.mnemonic == "call":
                    for r in VOLATILE:
                        regs.pop(r, None)
                    continue
                if insn.mnemonic == "lea" and len(insn.operands) == 2:
                    src = insn.operands[1]
                    if (src.type == x86c.X86_OP_MEM and
                            src.mem.base == x86c.X86_REG_RIP and
                            src.mem.index == 0):
                        va = insn.address + insn.size + src.mem.disp
                        # only set if not already clobbered
                        regs.setdefault(insn.operands[0].reg, va)

            def _add(s: Optional[str]):
                if _is_device_str(s) and s not in seen_strings:
                    seen_strings.add(s)
                    found.append(s)

            if func in ("RtlInitUnicodeString", "RtlUnicodeStringInit"):
                va = regs.get(x86c.X86_REG_RDX)
                if va:
                    _add(self._read_wide_str(va))
                # Also check rcx — sometimes the UNICODE_STRING itself
                # is pre-filled and passed as first arg
                va2 = regs.get(x86c.X86_REG_RCX)
                if va2:
                    s2 = self._read_wide_str(va2)
                    if _is_device_str(s2):
                        _add(s2)

            elif func in ("IoCreateSymbolicLink",
                           "IoCreateUnprotectedSymbolicLink",
                           "ZwCreateSymbolicLinkObject"):
                # rcx = &SymbolicLinkName, rdx = &DeviceName
                for reg in (x86c.X86_REG_RCX, x86c.X86_REG_RDX):
                    va = regs.get(reg)
                    if va:
                        s = self._read_unicode_string_struct(va)
                        if not _is_device_str(s):
                            s = self._read_wide_str(va)
                        _add(s)

            elif func in ("IoDeleteSymbolicLink", "ObReferenceObjectByName"):
                # rcx = &UNICODE_STRING (single arg of interest)
                va = regs.get(x86c.X86_REG_RCX)
                if va:
                    s = self._read_unicode_string_struct(va)
                    if not _is_device_str(s):
                        s = self._read_wide_str(va)
                    _add(s)

            elif func == "IoCreateDevice":
                # r8 = DeviceName (3rd param)
                va = regs.get(x86c.X86_REG_R8)
                if va:
                    s = self._read_unicode_string_struct(va)
                    if not _is_device_str(s):
                        s = self._read_wide_str(va)
                    _add(s)

            elif func in ("IoCreateDeviceSecure", "WdmlibIoCreateDeviceSecure"):
                # IoCreateDeviceSecure(DriverObj, ExtSize, DevName, DevType,
                #                     Characteristics, Exclusive, SDDL, ClassGuid, &DevObj)
                # r8 = DeviceName (3rd param, same as IoCreateDevice)
                va = regs.get(x86c.X86_REG_R8)
                if va:
                    s = self._read_unicode_string_struct(va)
                    if not _is_device_str(s):
                        s = self._read_wide_str(va)
                    _add(s)

            elif func in ("WdfDeviceCreateSymbolicLink",
                           "WdfDeviceCreateDeviceInterface"):
                # rdx = &SymbolicLinkName (2nd param)
                va = regs.get(x86c.X86_REG_RDX)
                if va:
                    s = self._read_unicode_string_struct(va)
                    if not _is_device_str(s):
                        s = self._read_wide_str(va)
                    _add(s)

            elif func == "IoRegisterDeviceInterface":
                # IoRegisterDeviceInterface(PDO, ClassGuid, RefStr, SymLinkName)
                # r8 = ReferenceString (3rd param, optional)
                va = regs.get(x86c.X86_REG_R8)
                if va:
                    s = self._read_wide_str(va)
                    if s and len(s) > 1:
                        _add(s)

            elif func == "__name_wrapper":
                # Intra-module helper that wraps one of the APIs above. We
                # don't know which arg slot carries the name, so try all of
                # rcx/rdx/r8/r9 and interpret each as either a raw wide
                # string or a UNICODE_STRING struct pointer.
                for reg in (x86c.X86_REG_RCX, x86c.X86_REG_RDX,
                            x86c.X86_REG_R8, x86c.X86_REG_R9):
                    va = regs.get(reg)
                    if not va:
                        continue
                    s = self._read_unicode_string_struct(va)
                    if not _is_device_str(s):
                        s = self._read_wide_str(va)
                    if _is_device_str(s):
                        _add(s)

        # Scan every code section
        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):  # not executable
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=10000)

            for i, insn in enumerate(insns):
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                call_target: Optional[int] = None
                if op.type == x86c.X86_OP_IMM:
                    call_target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    call_target = insn.address + insn.size + op.mem.disp

                if call_target in interesting:
                    _try_extract(insns, i, interesting[call_target])

        return found

    def scan_xor_encoded_strings(self, dis: Disassembler) -> List[str]:
        """
        Detect XOR-obfuscated device name strings.

        Common rootkit/driver pattern:
          1. Encrypted bytes stored as MOV [rbp/rsp+offset], DWORD_const
          2. Loop: read byte -> XOR with fixed key -> store as UTF-16LE word
        Decodes the bytes and returns strings that look like device paths.
        """
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        results: List[str] = []
        seen: set = set()

        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=20000)

            for i, insn in enumerate(insns):
                # Look for: xor al, imm  (single-byte XOR decrypt step)
                if not (insn.mnemonic == "xor" and len(insn.operands) == 2 and
                        insn.operands[0].type == x86c.X86_OP_REG and
                        insn.operands[0].reg in (x86c.X86_REG_AL, x86c.X86_REG_AX,
                                                  x86c.X86_REG_EAX) and
                        insn.operands[1].type == x86c.X86_OP_IMM):
                    continue

                xor_key = insn.operands[1].imm & 0xFF
                if xor_key == 0:
                    continue

                # Collect MOV [rbp/rsp + disp], imm  in the 60 insns before this XOR
                enc: Dict[int, int] = {}  # stack_offset -> encrypted_byte
                for prev in insns[max(0, i - 60): i]:
                    if not (prev.mnemonic in ("mov", "movb") and
                            len(prev.operands) == 2 and
                            prev.operands[0].type == x86c.X86_OP_MEM and
                            prev.operands[1].type == x86c.X86_OP_IMM):
                        continue
                    mem = prev.operands[0]
                    if mem.mem.base not in (x86c.X86_REG_RBP, x86c.X86_REG_RSP,
                                            x86c.X86_REG_EBP, x86c.X86_REG_ESP):
                        continue
                    disp = mem.mem.disp
                    imm  = prev.operands[1].imm
                    sz   = mem.size
                    if sz == 4:
                        for k in range(4):
                            enc[disp + k] = (imm >> (k * 8)) & 0xFF
                    elif sz == 1:
                        enc[disp] = imm & 0xFF
                    elif sz == 2:
                        enc[disp]     = imm & 0xFF
                        enc[disp + 1] = (imm >> 8) & 0xFF

                if len(enc) < 6:
                    continue

                # Reconstruct contiguous byte array from lowest offset
                min_off = min(enc.keys())
                byte_arr = []
                for off in range(min_off, min_off + len(enc) + 1):
                    if off in enc:
                        byte_arr.append(enc[off])
                    else:
                        break

                if len(byte_arr) < 6:
                    continue

                # XOR decode (single-byte key)
                decoded = bytes(b ^ xor_key for b in byte_arr)

                # Check if it looks like a device path (ASCII)
                # Require the name part after prefix to be at least 3 chars
                # and start with a letter to avoid binary noise
                device_prefixes = ("\\Device\\", "\\DosDevices\\",
                                   "\\GLOBAL??\\",
                                   "\\BaseNamedObjects\\", "\\FileSystem\\")
                try:
                    s = decoded.decode("ascii")
                    s = s.rstrip("\x00")
                    for pfx in device_prefixes:
                        if s.startswith(pfx):
                            name_part = s[len(pfx):]
                            if len(name_part) >= 3 and name_part[0].isalpha():
                                if s not in seen:
                                    seen.add(s)
                                    results.append(s)
                            break
                except Exception:
                    pass

                # Also try UTF-16LE XOR decode (XOR applied per-word)
                if len(byte_arr) >= 12 and len(byte_arr) % 2 == 0:
                    try:
                        decoded_w = bytes(b ^ xor_key for b in byte_arr)
                        s = decoded_w.decode("utf-16-le").rstrip("\x00")
                        for pfx in device_prefixes:
                            if s.startswith(pfx):
                                name_part = s[len(pfx):]
                                if len(name_part) >= 3 and name_part[0].isalpha():
                                    if s not in seen:
                                        seen.add(s)
                                        results.append(s)
                                break
                    except Exception:
                        pass

        # ── Multi-byte XOR scan on data sections ──────────────────────────
        # Some drivers store device names XOR'd with 2-4 byte keys in .data/.rdata
        # Only use long prefixes (>=8 bytes) to avoid false positives from short ones
        device_prefixes_bytes = [
            b"\\Device\\", b"\\DosDevices\\", b"\\GLOBAL??\\"
        ]
        for sec in self.pe.sections:
            if sec.Characteristics & 0x20000000:  # skip code sections
                continue
            sec_data = sec.get_data()
            if len(sec_data) < 24:
                continue
            for prefix in device_prefixes_bytes:
                plen = len(prefix)
                for key_len in (2, 4):
                    if plen < key_len + 4:
                        continue
                    for pos in range(0, len(sec_data) - plen - 20, 1):
                        key = bytes(sec_data[pos + j] ^ prefix[j]
                                    for j in range(key_len))
                        if all(b == 0 for b in key):
                            continue
                        ok = True
                        for j in range(key_len, plen):
                            if sec_data[pos + j] ^ key[j % key_len] != prefix[j]:
                                ok = False
                                break
                        if not ok:
                            continue
                        # Decrypt full string (up to 128 bytes)
                        dec = bytearray()
                        for j in range(128):
                            if pos + j >= len(sec_data):
                                break
                            b = sec_data[pos + j] ^ key[j % key_len]
                            if b == 0:
                                break
                            if b < 0x20 or b > 0x7E:
                                break
                            dec.append(b)
                        # Require at least 3 chars after prefix and starts with letter
                        if len(dec) >= plen + 3:
                            try:
                                s = dec.decode("ascii")
                                suffix = s[plen:]
                                if suffix and suffix[0].isalpha() and s not in seen:
                                    seen.add(s)
                                    results.append(s)
                            except Exception:
                                pass

        # ── Single-byte XOR on UTF-16LE data (XMM-stacked device strings) ──
        # Many drivers load 16-byte xmm constants from .rdata, spill to
        # stack, then XOR-decrypt with a single byte before calling
        # RtlInitUnicodeString. The encoded UTF-16LE pattern is
        # {prefix_byte ^ key, 0x00 ^ key, ...}, so every other byte is
        # the key itself. We scan every section trying every non-zero key.
        wide_prefixes = [
            ("\\Device\\", b"\\\x00D\x00e\x00v\x00i\x00c\x00e\x00\\\x00"),
            ("\\DosDevices\\",
             b"\\\x00D\x00o\x00s\x00D\x00e\x00v\x00i\x00c\x00e\x00s\x00\\\x00"),
            ("\\??\\", b"\\\x00?\x00?\x00\\\x00"),
            ("\\GLOBAL??\\",
             b"\\\x00G\x00L\x00O\x00B\x00A\x00L\x00?\x00?\x00\\\x00"),
        ]
        for sec in self.pe.sections:
            sec_data = sec.get_data()
            if len(sec_data) < 16:
                continue
            for _prefix_str, prefix in wide_prefixes:
                plen = len(prefix)
                limit = len(sec_data) - plen - 4
                if limit <= 0:
                    continue
                for pos in range(0, limit):
                    key = sec_data[pos] ^ prefix[0]
                    if key == 0:
                        continue
                    ok = True
                    for j in range(1, plen):
                        if sec_data[pos + j] ^ key != prefix[j]:
                            ok = False
                            break
                    if not ok:
                        continue
                    # Decrypt up to 256 bytes (128 wide chars) until NUL word
                    dec = bytearray()
                    for j in range(256):
                        if pos + j >= len(sec_data):
                            break
                        dec.append(sec_data[pos + j] ^ key)
                        if (len(dec) >= 2 and len(dec) % 2 == 0 and
                                dec[-1] == 0 and dec[-2] == 0):
                            dec = dec[:-2]
                            break
                    if len(dec) < plen + 2:
                        continue
                    try:
                        s = dec.decode("utf-16-le", errors="strict").rstrip("\x00")
                        # Trim at first non-printable
                        end = 0
                        for ch in s:
                            if 0x20 <= ord(ch) <= 0x7E:
                                end += 1
                            else:
                                break
                        s = s[:end]
                        if len(s) < len(_prefix_str) + 2:
                            continue
                        if s not in seen:
                            seen.add(s)
                            results.append(s)
                    except Exception:
                        pass

        return results

    def extract_xmm_stacked_device_names(self, dis: Disassembler) -> List[str]:
        """
        Emulate XMM-register loads + stack spills to recover device names
        that are built on the stack before RtlInitUnicodeString is called.

        Common obfuscation pattern (PoisonX.sys and similar):
            movdqa xmm0, [rip + C]        ; load 16-byte encrypted blob
            movdqa [rbp - 0x30], xmm0     ; spill encrypted blob to stack
            mov    [rbp - 0x20], imm      ; tail bytes
            call   xor_decoder            ; XOR-decrypts in place (or not)
            lea    rdx, [rbp - 0x30]      ; rdx = &wide_name
            call   [rip + RtlInitUnicodeString]

        The emulator reconstructs the stack buffer byte-by-byte, reads the
        rdx pointer offset, and tries every single-byte XOR key (including 0)
        looking for a valid UTF-16LE device path. Handles both GUID-style
        names (\\Device\\{...-...}) and regular names (\\DosDevices\\Name).
        """
        if not self.is_64bit:
            return []

        image_base = self.pe.OPTIONAL_HEADER.ImageBase

        # Functions whose call-site stack frame holds (or builds) the
        # wide string OR a UNICODE_STRING pointing at it. The any-
        # contiguous-run scan in _emulate_window catches both shapes.
        target_funcs = {
            "RtlInitUnicodeString", "RtlUnicodeStringInit",
            "IoCreateDevice", "IoCreateDeviceSecure",
            "WdmlibIoCreateDeviceSecure",
            "IoCreateSymbolicLink", "IoCreateUnprotectedSymbolicLink",
            "IoDeleteSymbolicLink",
            "ZwCreateSymbolicLinkObject",
            "IoRegisterDeviceInterface",
            "ObReferenceObjectByName",
        }
        target_iat = {addr for addr, name in self.iat_map.items()
                      if name in target_funcs}
        if not target_iat:
            return []

        # 1-level interprocedural: also emulate at call sites to intra-module
        # wrappers of the above APIs — the name may be built on the caller's
        # stack and passed by register.
        target_iat = target_iat | self._find_name_wrapper_funcs(dis, target_iat)

        # Capstone XMM register IDs (guard against version differences)
        XMM_REGS: set = set()
        for _n in range(16):
            _r = getattr(x86c, f"X86_REG_XMM{_n}", None)
            if _r is not None:
                XMM_REGS.add(_r)

        STACK_BASES = (x86c.X86_REG_RBP, x86c.X86_REG_RSP)
        RSP_REGS = (x86c.X86_REG_RSP,)

        DEVICE_PREFIXES = ("\\Device\\", "\\DosDevices\\",
                           "\\??\\", "\\GLOBAL??\\")

        results: List[str] = []
        seen: set = set()

        def _is_valid_device(s: str) -> bool:
            if len(s) < 8 or len(s) > 240:
                return False
            if not any(s.startswith(p) for p in DEVICE_PREFIXES):
                return False
            # Every char must be printable ASCII (device names never have
            # embedded non-ASCII in practice)
            return all(0x20 <= ord(c) <= 0x7E for c in s)

        def _read16(va: int) -> Optional[bytes]:
            rva = va - image_base
            data = self.get_bytes_at_rva(rva, 16)
            return data if len(data) == 16 else None

        def _decode_buffer(buf: bytes) -> Optional[str]:
            # Try key=0 first (unobfuscated), then 1..255
            for key in (0,) + tuple(range(1, 256)):
                dec = buf if key == 0 else bytes(b ^ key for b in buf)
                # Find UTF-16LE NUL terminator on even boundary
                end = len(dec)
                for i in range(0, len(dec) - 1, 2):
                    if dec[i] == 0 and dec[i + 1] == 0:
                        end = i
                        break
                # Trim to even length for UTF-16LE alignment
                if end % 2:
                    end -= 1
                chunk = dec[:end]
                if len(chunk) < 16:
                    continue
                try:
                    s = chunk.decode("utf-16-le", errors="strict")
                except Exception:
                    continue
                if _is_valid_device(s):
                    return s
            return None

        def _emulate_window(insns: list, call_idx: int) -> Optional[str]:
            # Walk back to the enclosing function boundary instead of a
            # fixed-size window. Boundary = most recent ret / int3-padding
            # immediately followed by a function prologue. Falls back to a
            # generous 600-insn cap so pathological functions still work.
            start = max(0, call_idx - 600)
            for j in range(call_idx - 1, start, -1):
                m = insns[j].mnemonic
                if m in ("ret", "retf"):
                    start = j + 1
                    break
                # int3 padding between functions (often 3-4 in a row)
                if m == "int3" and j > start and insns[j - 1].mnemonic == "int3":
                    start = j + 1
                    break
            window = insns[start:call_idx]

            xmm: Dict[int, bytes] = {}
            stack: Dict[int, int] = {}
            rsp_adj = 0
            lea_arg_offs: Dict[int, int] = {}  # reg -> stack offset

            def _norm(base_reg: int, disp: int) -> int:
                # Normalize stack offset to original-RSP frame
                if base_reg in RSP_REGS:
                    return disp + rsp_adj
                return disp

            for insn in window:
                mn = insn.mnemonic
                ops = insn.operands

                # Track RSP adjustments
                if len(ops) == 2 and ops[0].type == x86c.X86_OP_REG and \
                        ops[0].reg == x86c.X86_REG_RSP and \
                        ops[1].type == x86c.X86_OP_IMM:
                    if mn == "sub":
                        rsp_adj -= ops[1].imm
                    elif mn == "add":
                        rsp_adj += ops[1].imm

                # XMM/SSE loads and stores
                if mn in ("movdqa", "movdqu", "movaps", "movups", "movapd", "movupd") \
                        and len(ops) == 2:
                    d, s = ops
                    # XMM <- [rip+X]
                    if (d.type == x86c.X86_OP_REG and d.reg in XMM_REGS and
                            s.type == x86c.X86_OP_MEM and
                            s.mem.base == x86c.X86_REG_RIP and s.mem.index == 0):
                        va = insn.address + insn.size + s.mem.disp
                        blob = _read16(va)
                        if blob is not None:
                            xmm[d.reg] = blob
                        else:
                            xmm.pop(d.reg, None)
                    # [rbp/rsp+X] <- XMM
                    elif (d.type == x86c.X86_OP_MEM and
                            d.mem.base in STACK_BASES and d.mem.index == 0 and
                            s.type == x86c.X86_OP_REG and s.reg in XMM_REGS):
                        if s.reg in xmm:
                            off = _norm(d.mem.base, d.mem.disp)
                            blob = xmm[s.reg]
                            for k in range(16):
                                stack[off + k] = blob[k]
                    # XMM <- XMM (reg-to-reg copy)
                    elif (d.type == x86c.X86_OP_REG and d.reg in XMM_REGS and
                            s.type == x86c.X86_OP_REG and s.reg in XMM_REGS):
                        if s.reg in xmm:
                            xmm[d.reg] = xmm[s.reg]
                        else:
                            xmm.pop(d.reg, None)
                    # XMM ^ XMM (zero-idiom)
                    continue

                # pxor xmm, xmm (self-XOR = zero)
                if mn == "pxor" and len(ops) == 2:
                    d, s = ops
                    if (d.type == x86c.X86_OP_REG and d.reg in XMM_REGS and
                            s.type == x86c.X86_OP_REG and d.reg == s.reg):
                        xmm[d.reg] = b"\x00" * 16
                    continue

                # Immediate stack write: mov [rbp/rsp+X], imm
                if mn == "mov" and len(ops) == 2:
                    d, s = ops
                    if (d.type == x86c.X86_OP_MEM and
                            d.mem.base in STACK_BASES and d.mem.index == 0 and
                            s.type == x86c.X86_OP_IMM):
                        off = _norm(d.mem.base, d.mem.disp)
                        imm = s.imm & ((1 << 64) - 1)
                        sz = d.size
                        if sz in (1, 2, 4, 8):
                            for k in range(sz):
                                stack[off + k] = (imm >> (k * 8)) & 0xFF
                        continue

                # Track lea {rcx,rdx,r8,r9}, [rbp/rsp + X]  (any of these
                # may be the wide-string pointer depending on which
                # function we're feeding into)
                if mn == "lea" and len(ops) == 2:
                    d, s = ops
                    if (d.type == x86c.X86_OP_REG and
                            d.reg in (x86c.X86_REG_RCX, x86c.X86_REG_RDX,
                                      x86c.X86_REG_R8, x86c.X86_REG_R9) and
                            s.type == x86c.X86_OP_MEM and
                            s.mem.base in STACK_BASES and s.mem.index == 0):
                        lea_arg_offs[d.reg] = _norm(s.mem.base, s.mem.disp)

            if not stack:
                return None

            # Build candidate buffers:
            #   1. Region starting at each tracked lea-arg offset
            #   2. Every contiguous run >= 16 bytes in the stack model
            #      (catches encrypted blob when decoder writes to a
            #      different buffer than the source)
            candidates: List[bytes] = []
            for off in lea_arg_offs.values():
                buf = bytearray()
                cur = off
                while cur in stack and len(buf) < 256:
                    buf.append(stack[cur])
                    cur += 1
                if len(buf) >= 16:
                    candidates.append(bytes(buf))

            offsets = sorted(stack.keys())
            run = bytearray()
            run_start = None
            for off in offsets:
                if run_start is None or off == run_start + len(run):
                    if run_start is None:
                        run_start = off
                    run.append(stack[off])
                else:
                    if len(run) >= 16:
                        candidates.append(bytes(run))
                    run_start = off
                    run = bytearray([stack[off]])
            if len(run) >= 16:
                candidates.append(bytes(run))

            for cand in candidates:
                got = _decode_buffer(cand)
                if got:
                    return got
            return None

        # Scan every executable section for call sites
        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns = dis.disassemble_range(sec_data, sec_va, max_insns=30000)

            for i, insn in enumerate(insns):
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                tgt: Optional[int] = None
                if (op.type == x86c.X86_OP_MEM and
                        op.mem.base == x86c.X86_REG_RIP and op.mem.index == 0):
                    tgt = insn.address + insn.size + op.mem.disp
                elif op.type == x86c.X86_OP_IMM:
                    tgt = op.imm
                if tgt not in target_iat:
                    continue

                name = _emulate_window(insns, i)
                if name and name not in seen:
                    seen.add(name)
                    results.append(name)

        return results

    def extract_stack_packed_device_names(self, dis: "Disassembler") -> List[str]:
        """Recover device names built by packed immediate stores on the stack.

        Catches the non-XMM variant where the driver composes the wide
        string via a run of ``mov qword [rsp+X], imm64`` instructions and
        then passes the buffer to an internal helper (which is why the
        XMM extractor — keyed on an IAT call target — misses it).

        Walks each function, emulates every integer stack store of size
        1/2/4/8, assembles contiguous stack runs, and reports any run
        that decodes as ASCII or UTF-16LE to a known device prefix.
        """
        if not self.is_64bit:
            return []
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        results: List[str] = []
        seen: set = set()

        DEVICE_PREFIXES = ("\\Device\\", "\\DosDevices\\",
                           "\\??\\", "\\GLOBAL??\\")
        STACK_BASES = (x86c.X86_REG_RBP, x86c.X86_REG_RSP)

        def _looks_like_name(s: str) -> bool:
            if not (8 <= len(s) <= 240):
                return False
            if not any(s.startswith(p) for p in DEVICE_PREFIXES):
                return False
            return all(0x20 <= ord(c) <= 0x7E for c in s)

        def _decode_runs(stack: Dict[int, int]) -> List[str]:
            if not stack:
                return []
            offsets = sorted(stack.keys())
            runs: List[bytes] = []
            run = bytearray()
            run_start: Optional[int] = None
            for off in offsets:
                if run_start is None or off == run_start + len(run):
                    if run_start is None:
                        run_start = off
                    run.append(stack[off])
                else:
                    if len(run) >= 16:
                        runs.append(bytes(run))
                    run_start = off
                    run = bytearray([stack[off]])
            if len(run) >= 16:
                runs.append(bytes(run))

            names: List[str] = []
            for buf in runs:
                # UTF-16LE (primary — kernel APIs take PCWSTR)
                end = len(buf)
                for i in range(0, len(buf) - 1, 2):
                    if buf[i] == 0 and buf[i + 1] == 0:
                        end = i
                        break
                if end % 2:
                    end -= 1
                chunk = buf[:end]
                if len(chunk) >= 16:
                    try:
                        s = chunk.decode("utf-16-le", errors="strict")
                        if _looks_like_name(s):
                            names.append(s)
                            continue
                    except Exception:
                        pass
                # ASCII fallback
                nul = buf.find(b"\x00")
                end2 = nul if nul >= 0 else len(buf)
                try:
                    s = buf[:end2].decode("ascii", errors="strict")
                    if _looks_like_name(s):
                        names.append(s)
                except Exception:
                    pass
            return names

        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns = dis.disassemble_range(sec_data, sec_va, max_insns=30000)

            # Split into function-ish windows at ret / int3-padding runs.
            starts = [0]
            for j, insn in enumerate(insns):
                if insn.mnemonic in ("ret", "retf"):
                    starts.append(j + 1)
                elif (insn.mnemonic == "int3" and
                      j + 1 < len(insns) and insns[j + 1].mnemonic == "int3"):
                    starts.append(j + 1)

            for a, b in zip(starts, starts[1:] + [len(insns)]):
                if a >= len(insns):
                    continue
                window = insns[a:b]
                if len(window) < 6 or len(window) > 1500:
                    continue

                stack: Dict[int, int] = {}
                rsp_adj = 0
                saw_backslash = False

                for insn in window:
                    mn = insn.mnemonic
                    ops = insn.operands

                    # Track RSP adjustments
                    if (mn in ("sub", "add") and len(ops) == 2 and
                            ops[0].type == x86c.X86_OP_REG and
                            ops[0].reg == x86c.X86_REG_RSP and
                            ops[1].type == x86c.X86_OP_IMM):
                        rsp_adj += -ops[1].imm if mn == "sub" else ops[1].imm

                    # mov [rsp/rbp + X], imm
                    if mn == "mov" and len(ops) == 2:
                        d, s = ops
                        if (d.type == x86c.X86_OP_MEM and
                                d.mem.base in STACK_BASES and
                                d.mem.index == 0 and
                                s.type == x86c.X86_OP_IMM):
                            off = d.mem.disp
                            if d.mem.base == x86c.X86_REG_RSP:
                                off += rsp_adj
                            sz = d.size
                            if sz in (1, 2, 4, 8):
                                imm = s.imm & ((1 << 64) - 1)
                                for k in range(sz):
                                    by = (imm >> (k * 8)) & 0xFF
                                    stack[off + k] = by
                                    if by == 0x5C:  # '\'
                                        saw_backslash = True

                if not saw_backslash or not stack:
                    continue
                for s in _decode_runs(stack):
                    if s not in seen:
                        seen.add(s)
                        results.append(s)

        return results

    def extract_data_unicode_string_initializers(self, dis: "Disassembler"
                                                 ) -> List[str]:
        """Find UNICODE_STRINGs in ``.data`` initialized with a wide literal.

        DriverEntry often sets up a module-scope ``UNICODE_STRING g_DevName``
        then hands ``&g_DevName`` to ``IoCreateDevice``. The compiler emits::

            lea   rax, [rip + L"\\Device\\Foo"]       ; literal in .rdata
            mov   qword [rip + g_DevName + 8], rax    ; .Buffer = literal

        We locate every ``lea reg, [rip+literal]`` that is followed within
        a short window by ``mov [rip+var], reg`` where ``var`` lives in a
        writable section — that's the ``.Buffer`` slot of a UNICODE_STRING
        (or a pointer-typed global). The literal is then read as a wide
        string and emitted if it matches a device prefix.

        Complements the static string scan by (a) confirming which of
        possibly many ``\\Device\\...`` literals is actually registered
        as a device, and (b) picking up literals that sit outside the
        ranges the raw-byte regex scans.
        """
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        results: List[str] = []
        seen: set = set()

        writable_ranges: List[Tuple[int, int]] = []
        readable_ranges: List[Tuple[int, int]] = []
        for s in self.pe.sections:
            lo = image_base + s.VirtualAddress
            hi = lo + max(s.Misc_VirtualSize, s.SizeOfRawData)
            if s.Characteristics & 0x80000000:  # writable
                writable_ranges.append((lo, hi))
            if not (s.Characteristics & 0x20000000):  # not executable
                readable_ranges.append((lo, hi))

        def _in(ranges: List[Tuple[int, int]], va: int) -> bool:
            return any(lo <= va < hi for lo, hi in ranges)

        DEVICE_PREFIXES = ("\\Device\\", "\\DosDevices\\",
                           "\\??\\", "\\GLOBAL??\\")

        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=30000)

            for i, insn in enumerate(insns):
                if insn.mnemonic != "lea" or len(insn.operands) != 2:
                    continue
                d, s = insn.operands
                if not (d.type == x86c.X86_OP_REG and
                        s.type == x86c.X86_OP_MEM and
                        s.mem.base == x86c.X86_REG_RIP and
                        s.mem.index == 0):
                    continue
                literal_va = insn.address + insn.size + s.mem.disp
                if not _in(readable_ranges, literal_va):
                    continue
                wide = self._read_wide_str(literal_va)
                if not wide or not any(wide.startswith(p)
                                        for p in DEVICE_PREFIXES):
                    continue
                # ASCII name-part check — reject noise like "\Device\\x00..."
                tail = next((wide[len(p):] for p in DEVICE_PREFIXES
                             if wide.startswith(p)), "")
                if len(tail) < 2 or not tail[0].isalnum():
                    continue

                reg = d.reg
                # Look ahead ≤ 10 insns for a mov [rip+var], reg that stores
                # the literal pointer into a writable global.
                for nxt in insns[i + 1: i + 11]:
                    mn = nxt.mnemonic
                    if mn == "call":
                        break
                    if mn == "mov" and len(nxt.operands) == 2:
                        dd, ss = nxt.operands
                        if (dd.type == x86c.X86_OP_MEM and
                                dd.mem.base == x86c.X86_REG_RIP and
                                dd.mem.index == 0 and
                                ss.type == x86c.X86_OP_REG and ss.reg == reg):
                            var_va = nxt.address + nxt.size + dd.mem.disp
                            if _in(writable_ranges, var_va):
                                if wide not in seen:
                                    seen.add(wide)
                                    results.append(wide)
                            break
                    # Any other write to reg clobbers the pointer
                    if (nxt.operands and
                            nxt.operands[0].type == x86c.X86_OP_REG and
                            nxt.operands[0].reg == reg and
                            mn in ("mov", "lea", "xor", "add", "sub",
                                   "and", "or", "pop")):
                        break

        return results

    def find_format_device_names(self) -> List[str]:
        """Find format-string device name templates like \\DosDevices\\Name%d.
        These are used with RtlStringCbPrintfW / swprintf_s to construct
        the final device name at runtime with a unique suffix.
        """
        results: List[str] = []
        seen: set = set()
        # ASCII
        ascii_pats = [
            rb"\\Device\\[A-Za-z0-9_]+%[0-9]*[dsuxi]",
            rb"\\DosDevices\\[A-Za-z0-9_]+%[0-9]*[dsuxi]",
            rb"\\\?\?\\[A-Za-z0-9_]+%[0-9]*[dsuxi]",
            rb"\\GLOBAL\?\?\\[A-Za-z0-9_]+%[0-9]*[dsuxi]",
        ]
        for pat in ascii_pats:
            for m in re.finditer(pat, self.raw):
                s = m.group().decode("ascii", errors="replace")
                if s not in seen:
                    seen.add(s)
                    results.append(s)
        # UTF-16LE
        wide_pats = [
            rb"\\\x00D\x00e\x00v\x00i\x00c\x00e\x00\\\x00"
            rb"(?:[A-Za-z0-9_]\x00){3,}%\x00[0-9]?\x00?[dsuxi]\x00",
            rb"\\\x00D\x00o\x00s\x00D\x00e\x00v\x00i\x00c\x00e\x00s\x00\\\x00"
            rb"(?:[A-Za-z0-9_]\x00){3,}%\x00[0-9]?\x00?[dsuxi]\x00",
        ]
        for pat in wide_pats:
            for m in re.finditer(pat, self.raw):
                try:
                    s = m.group().decode("utf-16-le", errors="replace").rstrip("\x00")
                    if s not in seen:
                        seen.add(s)
                        results.append(s)
                except Exception:
                    pass
        return results

    def extract_dynamic_device_templates(self, dis: "Disassembler") -> List[str]:
        """Surface drivers that compose device names at runtime.

        Some drivers (EnCase EnPortv.sys / Slayer.sys, vendor mini-filters,
        etc.) carry only bare prefix strings like ``\\Device\\`` /
        ``\\DosDevices\\`` followed by a NUL, and build the real name at
        runtime via ``RtlAppendUnicodeStringToString``, ``swprintf_s``, or
        by reading the service name out of
        ``\\REGISTRY\\Machine\\System\\CurrentControlSet\\Services\\<name>``.
        The static-data scan returns nothing usable for these drivers, so
        this method looks for the *composition pattern* and emits
        templates the user can attach to — for example::

            \\Device\\<ServiceName>
            \\DosDevices\\<ServiceName>
            \\Device\\_root_         (when the driver carries the
            \\DosDevices\\_root_      root-enumerated fallback string)

        The templates are advisory — they tell the reader "the name is
        runtime-derived, so hook IoCreateDevice to recover the literal."
        """
        results: List[str] = []
        seen: set = set()
        raw = self.raw

        # ── 1. Look for bare prefixes (prefix immediately followed by NUL) ──
        utf16_bare = [
            ("\\Device\\",
             b"\\\x00D\x00e\x00v\x00i\x00c\x00e\x00\\\x00\x00\x00"),
            ("\\DosDevices\\",
             b"\\\x00D\x00o\x00s\x00D\x00e\x00v\x00i\x00c\x00e\x00s\x00\\\x00\x00\x00"),
            ("\\??\\",
             b"\\\x00?\x00?\x00\\\x00\x00\x00"),
            ("\\GLOBAL??\\",
             b"\\\x00G\x00L\x00O\x00B\x00A\x00L\x00?\x00?\x00\\\x00\x00\x00"),
        ]
        ascii_bare = [
            ("\\Device\\",      b"\\Device\\\x00"),
            ("\\DosDevices\\",  b"\\DosDevices\\\x00"),
            ("\\??\\",          b"\\??\\\x00"),
            ("\\GLOBAL??\\",    b"\\GLOBAL??\\\x00"),
        ]
        bare_found: set = set()
        for prefix, needle in utf16_bare + ascii_bare:
            if needle in raw:
                bare_found.add(prefix)
        if not bare_found:
            return []

        # ── 2. Composition / registry-service signals via IAT ───────────────
        compose_apis = {
            "RtlAppendUnicodeStringToString", "RtlAppendUnicodeToString",
            "RtlCopyUnicodeString", "RtlInitUnicodeString",
            "RtlStringCbPrintfW", "RtlStringCbCatW",
            "RtlStringCchPrintfW", "RtlStringCchCatW", "RtlStringCchCopyW",
            "RtlUnicodeStringPrintf", "RtlAnsiStringToUnicodeString",
            "RtlUnicodeStringCat", "RtlUnicodeStringCopy",
            "swprintf", "swprintf_s", "_snwprintf", "_vsnwprintf",
            "wcscat", "wcscat_s", "wcscpy", "wcscpy_s", "wcsncpy", "wcsncat",
        }
        registry_apis = {
            "ZwQueryValueKey", "ZwOpenKey", "ZwEnumerateValueKey",
            "RtlQueryRegistryValues", "IoRegisterDeviceInterface",
            "IoOpenDeviceRegistryKey",
        }
        imported = set(self.iat_map.values())
        has_compose  = bool(imported & compose_apis)
        has_registry = bool(imported & registry_apis)
        if not (has_compose or has_registry):
            return []

        # ── 3. Service-name-from-registry signals ──────────────────────────
        services_ascii = b"CurrentControlSet\\Services"
        services_wide  = services_ascii.decode().encode("utf-16-le")
        has_services = services_ascii in raw or services_wide in raw
        has_root = (b"_root_" in raw
                    or b"_\x00r\x00o\x00o\x00t\x00_\x00" in raw)

        # Pick the most informative placeholder.
        if has_services and has_registry:
            placeholder = "<ServiceName>"
        elif has_compose:
            placeholder = "<runtime>"
        else:
            placeholder = "<runtime>"

        # ── 4. Emit templates for each bare prefix ─────────────────────────
        PREFERRED = ("\\Device\\", "\\DosDevices\\", "\\??\\", "\\GLOBAL??\\")
        for prefix in PREFERRED:
            if prefix not in bare_found:
                continue
            tpl = f"{prefix}{placeholder}"
            if tpl not in seen:
                seen.add(tpl)
                results.append(tpl)

        # A bare \DosDevices\ symlink implies a matching \Device\ device —
        # the driver would have no reason to register one without the other.
        # Mirror the pair so consumers get both sides of the template.
        if "\\DosDevices\\" in bare_found and "\\Device\\" not in bare_found:
            tpl = f"\\Device\\{placeholder}"
            if tpl not in seen:
                seen.add(tpl)
                results.insert(0, tpl)  # list \Device\ first for readability
        if "\\Device\\" in bare_found and "\\DosDevices\\" not in bare_found:
            tpl = f"\\DosDevices\\{placeholder}"
            if tpl not in seen:
                seen.add(tpl)
                results.append(tpl)

        # Root-enumerated fallback: drivers that check for "_root_" when
        # the registry key is missing will expose \Device\_root_ / symlink.
        if has_root and has_services:
            for prefix in ("\\Device\\", "\\DosDevices\\"):
                # Emit fallback even if the matching bare prefix wasn't found
                # — the pair inference above already covered that case.
                s = f"{prefix}_root_"
                if s not in seen:
                    seen.add(s)
                    results.append(s)

        return results

    def extract_registry_service_names(self) -> Tuple[List[str], List[str]]:
        """Recover device names that a driver pulls from its service registry
        key at runtime (``\\Registry\\Machine\\System\\CurrentControlSet\\
        Services\\<svc>``).

        Returns ``(device_name_templates, registry_refs)``:

          * ``device_name_templates`` — concrete ``\\Device\\<svc>`` /
            ``\\DosDevices\\<svc>`` entries derived from service-name
            literals, safe to merge into ``device_names``.
          * ``registry_refs`` — informational ``Registry:<path>`` and
            ``RegistryValue:<name>`` hints about which keys/values the
            driver reads. These are NOT device names and should be
            surfaced separately.
        """
        templates: List[str] = []
        refs: List[str] = []
        seen_tpl: set = set()
        seen_ref: set = set()

        imported = set(self.iat_map.values())
        registry_apis = {
            "RtlQueryRegistryValues", "ZwOpenKey", "ZwQueryValueKey",
            "ZwEnumerateValueKey", "ZwEnumerateKey",
            "IoOpenDeviceRegistryKey", "IoOpenDeviceInterfaceRegistryKey",
            "IoGetDeviceProperty", "RtlCreateRegistryKey",
        }
        has_registry = bool(imported & registry_apis)

        # ── A. Full registry path literals ────────────────────────────────
        reg_patterns = [
            rb"\\Registry\\Machine\\[A-Za-z0-9_\\\-\.]{4,}",
            rb"\\REGISTRY\\MACHINE\\[A-Za-z0-9_\\\-\.]{4,}",
        ]
        for pat in reg_patterns:
            for m in re.finditer(pat, self.raw):
                s = m.group().decode("ascii", errors="replace")
                key = f"Registry:{s}"
                if key not in seen_ref:
                    seen_ref.add(key)
                    refs.append(key)

        # UTF-16LE registry paths
        wide_reg_prefixes = [
            b"\\\x00R\x00e\x00g\x00i\x00s\x00t\x00r\x00y\x00"
            b"\\\x00M\x00a\x00c\x00h\x00i\x00n\x00e\x00\\\x00",
            b"\\\x00R\x00E\x00G\x00I\x00S\x00T\x00R\x00Y\x00"
            b"\\\x00M\x00A\x00C\x00H\x00I\x00N\x00E\x00\\\x00",
        ]
        raw = self.raw
        for prefix_bytes in wide_reg_prefixes:
            start = 0
            while True:
                idx = raw.find(prefix_bytes, start)
                if idx == -1:
                    break
                start = idx + 1
                end = idx + len(prefix_bytes)
                while end + 1 < len(raw):
                    ch = raw[end] | (raw[end + 1] << 8)
                    if ch == 0:
                        break
                    if ch < 0x20 or ch > 0x7E:
                        break
                    end += 2
                chunk = raw[idx:end]
                if len(chunk) < len(prefix_bytes) + 6:
                    continue
                try:
                    s = chunk.decode("utf-16-le").rstrip("\x00")
                    key = f"Registry:{s}"
                    if key not in seen_ref:
                        seen_ref.add(key)
                        refs.append(key)
                except Exception:
                    pass

        # ── B. Known value names that carry device names ─────────────────
        value_names = [b"DeviceName", b"SymbolicLink", b"NtName",
                       b"DosName", b"ObjectName", b"LinkName"]
        for vn in value_names:
            # Require a NUL terminator after the value name to reduce
            # false positives from substrings of longer identifiers.
            if (vn + b"\x00") in raw:
                key = f"RegistryValue:{vn.decode()}"
                if key not in seen_ref:
                    seen_ref.add(key)
                    refs.append(key)
                continue
            # UTF-16LE form
            wide = vn.decode().encode("utf-16-le") + b"\x00\x00"
            if wide in raw:
                key = f"RegistryValue:{vn.decode()}"
                if key not in seen_ref:
                    seen_ref.add(key)
                    refs.append(key)

        # ── C. Concrete \Device\<svc> / \DosDevices\<svc> templates ──────
        # When a Services\<name> path appears AND registry-reading APIs are
        # imported, the driver is almost certainly loading the device name
        # from its own service key — emit a concrete template.
        if has_registry:
            svc_patterns = [
                rb"\\Services\\([A-Za-z_][A-Za-z0-9_\-]{2,63})",
                rb"\\SERVICES\\([A-Za-z_][A-Za-z0-9_\-]{2,63})",
            ]
            svc_names: set = set()
            for pat in svc_patterns:
                for m in re.finditer(pat, raw):
                    svc = m.group(1).decode("ascii", errors="replace")
                    if svc.lower() not in ("parameters", "config", "enum",
                                           "security"):
                        svc_names.add(svc)
            # Wide form
            wide_svc = rb"\\\x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00s\x00\\\x00"
            for m in re.finditer(wide_svc, raw):
                pos = m.end()
                end = pos
                while end + 1 < len(raw):
                    ch = raw[end] | (raw[end + 1] << 8)
                    if ch == 0 or ch == 0x5C:  # NUL or '\'
                        break
                    if ch < 0x20 or ch > 0x7E:
                        break
                    end += 2
                try:
                    svc = raw[pos:end].decode("utf-16-le")
                    if (len(svc) >= 3 and svc[0].isalpha() and
                            svc.lower() not in ("parameters", "config",
                                                "enum", "security")):
                        svc_names.add(svc)
                except Exception:
                    pass

            for svc in svc_names:
                for prefix in ("\\Device\\", "\\DosDevices\\"):
                    tpl = f"{prefix}{svc}"
                    if tpl not in seen_tpl:
                        seen_tpl.add(tpl)
                        templates.append(tpl)

        return templates, refs

    def extract_concat_device_names(self, dis: "Disassembler") -> List[str]:
        """Recover device names built at runtime by string-concatenation
        helpers (``RtlAppendUnicodeToString``, ``wcscpy``/``wcscat``,
        ``swprintf``, etc.).

        For each call site we grab the literal wide string passed in ``rdx``
        (2nd arg on x64) via back-tracking ``lea rdx, [rip+X]``. Within a
        single function window we then pair each concat suffix with the
        most-recent base that starts with a device prefix, emitting the
        composed name.
        """
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        results: List[str] = []
        seen: set = set()

        CONCAT_APIS = {
            "RtlAppendUnicodeToString", "RtlAppendUnicodeStringToString",
            "RtlUnicodeStringPrintf", "RtlUnicodeStringCbPrintfW",
            "RtlStringCbCopyW", "RtlStringCchCopyW",
            "RtlStringCbCatW",  "RtlStringCchCatW",
            "RtlStringCbPrintfW", "RtlStringCchPrintfW",
            "wcscpy", "wcscpy_s", "wcscat", "wcscat_s",
            "wcsncpy", "wcsncpy_s", "wcsncat", "wcsncat_s",
            "swprintf", "swprintf_s", "_snwprintf", "_snwprintf_s",
            "_vsnwprintf", "_vsnwprintf_s",
        }
        interesting: Dict[int, str] = {
            addr: name for addr, name in self.iat_map.items()
            if name in CONCAT_APIS
        }
        if not interesting:
            return []

        DEVICE_PREFIXES = ("\\Device\\", "\\DosDevices\\",
                           "\\??\\", "\\GLOBAL??\\")

        def _is_device_prefix(s: Optional[str]) -> bool:
            return bool(s and any(s.startswith(p) for p in DEVICE_PREFIXES))

        def _looks_valid(name: str) -> bool:
            if len(name) < 6 or len(name) > 200:
                return False
            if not _is_device_prefix(name):
                return False
            # Trim any trailing format specifier leftovers or whitespace
            # for the "looks valid" check.
            tail = next((name[len(p):] for p in DEVICE_PREFIXES
                         if name.startswith(p)), "")
            if len(tail) < 2:
                return False
            return tail[0].isalnum() or tail[0] in ("_", "{")

        VOLATILE = (x86c.X86_REG_RCX, x86c.X86_REG_RDX, x86c.X86_REG_R8,
                    x86c.X86_REG_R9, x86c.X86_REG_RAX, x86c.X86_REG_R10,
                    x86c.X86_REG_R11)

        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=20000)

            # Split into rough function windows so a base/suffix pairing
            # doesn't cross function boundaries.
            starts = [0]
            for j, insn in enumerate(insns):
                if insn.mnemonic in ("ret", "retf"):
                    starts.append(j + 1)

            for a, b in zip(starts, starts[1:] + [len(insns)]):
                if a >= len(insns):
                    continue
                window = insns[a:b]
                if len(window) < 2:
                    continue

                # Per-function state: last seen base (starts with device prefix)
                last_base: Optional[str] = None

                for i, insn in enumerate(window):
                    if insn.mnemonic != "call" or not insn.operands:
                        continue
                    op = insn.operands[0]
                    target: Optional[int] = None
                    if op.type == x86c.X86_OP_IMM:
                        target = op.imm
                    elif (op.type == x86c.X86_OP_MEM and
                          op.mem.base == x86c.X86_REG_RIP and
                          op.mem.index == 0):
                        target = insn.address + insn.size + op.mem.disp
                    if target not in interesting:
                        continue

                    api_name = interesting[target]

                    # Backward-track lea reg, [rip+X] for rdx/r8
                    # Reset on intervening calls (volatile regs clobbered).
                    regs: Dict[int, int] = {}
                    lo = max(0, i - 30)
                    for prev in reversed(window[lo:i]):
                        if prev.mnemonic == "call":
                            for r in VOLATILE:
                                regs.pop(r, None)
                            continue
                        if (prev.mnemonic == "lea" and len(prev.operands) == 2):
                            src = prev.operands[1]
                            if (src.type == x86c.X86_OP_MEM and
                                    src.mem.base == x86c.X86_REG_RIP and
                                    src.mem.index == 0):
                                va = prev.address + prev.size + src.mem.disp
                                regs.setdefault(prev.operands[0].reg, va)

                    # Pull the src wide string from rdx (2nd arg) for most APIs.
                    # For RtlAppendUnicodeStringToString, rdx is a
                    # UNICODE_STRING* — try that form first.
                    src_str: Optional[str] = None
                    rdx_va = regs.get(x86c.X86_REG_RDX)
                    if rdx_va:
                        if api_name == "RtlAppendUnicodeStringToString":
                            src_str = self._read_unicode_string_struct(rdx_va)
                            if not src_str:
                                src_str = self._read_wide_str(rdx_va)
                        else:
                            src_str = self._read_wide_str(rdx_va)

                    if not src_str:
                        continue

                    # Case 1: the literal is itself a full device path
                    if _is_device_prefix(src_str):
                        clean = src_str.rstrip("\x00").split("\x00", 1)[0]
                        if _looks_valid(clean) and clean not in seen:
                            seen.add(clean)
                            results.append(clean)
                        # Also remember it as a base for any following suffix
                        if _is_device_prefix(clean):
                            last_base = clean
                        continue

                    # Case 2: looks like a suffix (short alphanumeric) —
                    # pair with the most recent base we saw in this window.
                    if (last_base and 0 < len(src_str) <= 64 and
                            all((ch.isalnum() or ch in "_-{}#.\\")
                                for ch in src_str.rstrip("\x00"))):
                        suffix = src_str.rstrip("\x00")
                        if not suffix:
                            continue
                        # Compose base + suffix (ensure no double-slash glitch)
                        if last_base.endswith("\\") or suffix.startswith("\\"):
                            composed = last_base + suffix
                        else:
                            composed = last_base + suffix
                        if _looks_valid(composed) and composed not in seen:
                            seen.add(composed)
                            results.append(composed)

                    # Case 3: fmt string for RtlStringCbPrintfW /
                    # swprintf — if it embeds a device prefix followed by a
                    # format specifier, emit it as a template.
                    if ("%s" in src_str or "%ws" in src_str or
                            "%d" in src_str or "%u" in src_str):
                        for pfx in DEVICE_PREFIXES:
                            if pfx in src_str:
                                idx_pfx = src_str.index(pfx)
                                tpl = src_str[idx_pfx:].rstrip("\x00")
                                tpl = tpl.split("\x00", 1)[0]
                                if len(tpl) > len(pfx) + 1 and tpl not in seen:
                                    seen.add(tpl)
                                    results.append(tpl)
                                break

        return results

    def resolve_mm_get_system_routine_address(self, dis: "Disassembler") -> int:
        """Detect ``MmGetSystemRoutineAddress(L"ApiName")`` calls and
        register the returned function pointer's storage VA as a synthetic
        IAT entry — so all existing tracers that look up
        ``self.iat_map[call_target]`` automatically resolve subsequent
        indirect calls through that pointer.

        Handles typical patterns::

            lea    rcx, [rip+L"IoCreateSymbolicLink"]
            call   qword ptr [rip+__imp_MmGetSystemRoutineAddress]
            mov    [rip+g_pIoCreateSymbolicLink], rax       ; global sink
            ...
            mov    rax, [rip+g_pIoCreateSymbolicLink]
            call   rax

        or::

            call   qword ptr [rip+g_pIoCreateSymbolicLink]

        Returns the number of resolutions added to ``self.iat_map``.
        """
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        mmgsra_addr: Optional[int] = None
        for addr, name in self.iat_map.items():
            if name == "MmGetSystemRoutineAddress":
                mmgsra_addr = addr
                break
        if mmgsra_addr is None:
            return 0

        added = 0
        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=20000)

            for i, insn in enumerate(insns):
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                target: Optional[int] = None
                if op.type == x86c.X86_OP_IMM:
                    target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    target = insn.address + insn.size + op.mem.disp
                if target != mmgsra_addr:
                    continue

                # Back-track rcx for the L"ApiName" string literal
                api_name_va: Optional[int] = None
                for prev in reversed(insns[max(0, i - 20): i]):
                    if prev.mnemonic == "call":
                        break
                    if (prev.mnemonic == "lea" and len(prev.operands) == 2 and
                            prev.operands[0].type == x86c.X86_OP_REG and
                            prev.operands[0].reg in (x86c.X86_REG_RCX,
                                                      x86c.X86_REG_ECX)):
                        src = prev.operands[1]
                        if (src.type == x86c.X86_OP_MEM and
                                src.mem.base == x86c.X86_REG_RIP and
                                src.mem.index == 0):
                            api_name_va = prev.address + prev.size + src.mem.disp
                            break
                if not api_name_va:
                    continue
                api_name = self._read_wide_str(api_name_va)
                # Sanity: a real API name is short, ASCII, identifier-like.
                if (not api_name or len(api_name) < 3 or len(api_name) > 64 or
                        not all((ch.isalnum() or ch == "_") for ch in api_name)):
                    continue

                # Forward-track: look for the first mov [rip+DISP], rax
                # within a handful of instructions (rax clobbered by any
                # subsequent call).
                for fwd in insns[i + 1: i + 15]:
                    if fwd.mnemonic == "call":
                        break
                    if (fwd.mnemonic == "mov" and len(fwd.operands) == 2 and
                            fwd.operands[1].type == x86c.X86_OP_REG and
                            fwd.operands[1].reg in (x86c.X86_REG_RAX,
                                                     x86c.X86_REG_EAX)):
                        dst = fwd.operands[0]
                        if (dst.type == x86c.X86_OP_MEM and
                                dst.mem.base == x86c.X86_REG_RIP and
                                dst.mem.index == 0):
                            storage_va = fwd.address + fwd.size + dst.mem.disp
                            # Only insert if not already mapped (don't
                            # overwrite a legitimate IAT slot).
                            if storage_va not in self.iat_map:
                                self.iat_map[storage_va] = api_name
                                added += 1
                            break
        return added

    def extract_stack_unicode_string_names(self, dis: "Disassembler") -> List[str]:
        """Recover device/symlink names passed via stack-built UNICODE_STRING
        structs.

        Pattern the baseline RIP-relative tracer misses::

            mov   word ptr [rsp+0x20], 0x2C         ; Length
            mov   word ptr [rsp+0x22], 0x2E         ; MaxLength
            lea   rax, [rip+string_literal]
            mov   qword ptr [rsp+0x28], rax         ; Buffer (UNICODE_STRING+8)
            lea   rcx, [rsp+0x20]                   ; &UNICODE_STRING on stack
            call  IoCreateSymbolicLink

        We scan for calls to naming APIs where the arg register is loaded
        via ``lea reg, [rsp+N]`` / ``lea reg, [rbp+N]`` (instead of the
        ``lea reg, [rip+X]`` case the baseline handles) and resolve the
        Buffer field write at ``[rsp+N+8]`` back to a RIP-relative
        string literal.
        """
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        results: List[str] = []
        seen: set = set()

        # (API name, tuple of arg registers that hold &UNICODE_STRING)
        # Note: RtlInitUnicodeString fills the struct; not consumed — skipped.
        API_SLOTS: Dict[str, Tuple[int, ...]] = {
            "IoCreateDevice":                  (x86c.X86_REG_R8,),
            "IoCreateDeviceSecure":            (x86c.X86_REG_R8,),
            "WdmlibIoCreateDeviceSecure":      (x86c.X86_REG_R8,),
            "IoCreateSymbolicLink":            (x86c.X86_REG_RCX, x86c.X86_REG_RDX),
            "IoCreateUnprotectedSymbolicLink": (x86c.X86_REG_RCX, x86c.X86_REG_RDX),
            "IoDeleteSymbolicLink":            (x86c.X86_REG_RCX,),
            "ZwCreateSymbolicLinkObject":      (x86c.X86_REG_R9,),  # LinkTarget
            "WdfDeviceCreateSymbolicLink":     (x86c.X86_REG_RDX,),
            "WdfDeviceInitAssignName":         (x86c.X86_REG_RDX,),
            "ObReferenceObjectByName":         (x86c.X86_REG_RCX,),
        }
        interesting: Dict[int, Tuple[int, ...]] = {}
        for addr, name in self.iat_map.items():
            if name in API_SLOTS:
                interesting[addr] = API_SLOTS[name]
        if not interesting:
            return []

        DEVICE_PREFIXES = ("\\Device\\", "\\DosDevices\\",
                           "\\??\\", "\\GLOBAL??\\")

        def _is_device_str(s: Optional[str]) -> bool:
            return bool(s and len(s) > 4 and
                        any(s.startswith(p) for p in DEVICE_PREFIXES))

        VOLATILE = {x86c.X86_REG_RCX, x86c.X86_REG_RDX, x86c.X86_REG_R8,
                    x86c.X86_REG_R9, x86c.X86_REG_RAX, x86c.X86_REG_R10,
                    x86c.X86_REG_R11}
        STACK_BASES = (x86c.X86_REG_RSP, x86c.X86_REG_RBP,
                       x86c.X86_REG_ESP, x86c.X86_REG_EBP)

        def _resolve_buffer(window, base_reg, base_disp):
            """Within ``window`` (list of insns up to — but not including —
            the target call), find the latest ``mov [base_reg+base_disp+8], reg``
            and trace ``reg`` back to a ``lea reg, [rip+X]`` to read the string.
            """
            buffer_offset = base_disp + 8
            for idx in range(len(window) - 1, -1, -1):
                ins = window[idx]
                if ins.mnemonic != "mov" or len(ins.operands) != 2:
                    continue
                dst, src = ins.operands
                if (dst.type != x86c.X86_OP_MEM or
                        dst.mem.base != base_reg or
                        dst.mem.disp != buffer_offset):
                    continue
                if src.type == x86c.X86_OP_IMM and src.imm:
                    # Absolute pointer stored directly (rare, PIC-unfriendly)
                    return self._read_wide_str(src.imm)
                if src.type != x86c.X86_OP_REG:
                    return None
                # Walk earlier insns for lea src.reg, [rip+X]; bail at call
                for earlier in reversed(window[:idx]):
                    if earlier.mnemonic == "call":
                        break
                    if (earlier.mnemonic == "lea" and
                            len(earlier.operands) == 2 and
                            earlier.operands[0].type == x86c.X86_OP_REG and
                            earlier.operands[0].reg == src.reg):
                        e_src = earlier.operands[1]
                        if (e_src.type == x86c.X86_OP_MEM and
                                e_src.mem.base == x86c.X86_REG_RIP and
                                e_src.mem.index == 0):
                            va = earlier.address + earlier.size + e_src.mem.disp
                            return self._read_wide_str(va)
                return None
            return None

        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=20000)

            for i, insn in enumerate(insns):
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                target: Optional[int] = None
                if op.type == x86c.X86_OP_IMM:
                    target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    target = insn.address + insn.size + op.mem.disp
                if target not in interesting:
                    continue

                slots = interesting[target]

                # Back-track to find `lea slot_reg, [rsp/rbp + N]`.
                # A call encountered going backward clobbers any volatile
                # reg set BEFORE it, so we track a "blocked" set.
                reg_to_stack: Dict[int, Tuple[int, int]] = {}
                blocked: set = set()
                lo = max(0, i - 40)
                for prev in reversed(insns[lo:i]):
                    if prev.mnemonic == "call":
                        blocked |= VOLATILE
                        continue
                    if prev.mnemonic != "lea" or len(prev.operands) != 2:
                        continue
                    dst = prev.operands[0]
                    src = prev.operands[1]
                    if (dst.type == x86c.X86_OP_REG and
                            dst.reg not in blocked and
                            src.type == x86c.X86_OP_MEM and
                            src.mem.base in STACK_BASES and
                            src.mem.index == 0):
                        reg_to_stack.setdefault(
                            dst.reg, (src.mem.base, src.mem.disp))

                for slot_reg in slots:
                    stack_ref = reg_to_stack.get(slot_reg)
                    if not stack_ref:
                        continue
                    base_reg, base_disp = stack_ref
                    resolved = _resolve_buffer(insns[lo:i], base_reg, base_disp)
                    if _is_device_str(resolved) and resolved not in seen:
                        seen.add(resolved)
                        results.append(resolved)

        return results

    def extract_object_attributes_names(self, dis: "Disassembler") -> List[str]:
        """Resolve device/symlink names passed via ``POBJECT_ATTRIBUTES``.

        Many drivers reach the Object Manager through the Nt/Zw layer
        (``ZwCreateSymbolicLinkObject``, ``ZwOpenFile``, ``ZwCreateKey``,
        ``FltCreateCommunicationPort`` …). These APIs all take an
        ``OBJECT_ATTRIBUTES`` struct (48 bytes on x64) whose ``ObjectName``
        field at offset ``0x10`` is a ``PUNICODE_STRING``.

        For each relevant call we back-track the register holding the OA
        pointer. Two cases:

          * ``lea reg, [rip+X]`` — OA sits in ``.rdata``. We read the
            ``ObjectName`` qword at ``X+0x10`` and dereference as a
            ``UNICODE_STRING`` struct.
          * ``lea reg, [rsp+N]`` — OA built on the stack. We find the
            ``mov qword ptr [rsp+N+0x10], reg2`` write that sets the
            ``ObjectName`` pointer, then resolve ``reg2`` to either a
            ``.rdata`` UNICODE_STRING (via ``lea reg2, [rip+Y]``) or a
            stack UNICODE_STRING whose Buffer is itself populated via
            ``lea reg3, [rip+Z]``.
        """
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        results: List[str] = []
        seen: set = set()

        # API name -> arg slot (register) that holds POBJECT_ATTRIBUTES
        OA_APIS: Dict[str, int] = {
            "ZwCreateSymbolicLinkObject":    x86c.X86_REG_R8,
            "ZwOpenSymbolicLinkObject":      x86c.X86_REG_R8,
            "NtOpenSymbolicLinkObject":      x86c.X86_REG_R8,
            "ZwOpenFile":                    x86c.X86_REG_R8,
            "ZwCreateFile":                  x86c.X86_REG_R8,
            "ZwOpenKey":                     x86c.X86_REG_R8,
            "ZwOpenKeyEx":                   x86c.X86_REG_R8,
            "ZwCreateKey":                   x86c.X86_REG_R8,
            "IoCreateFile":                  x86c.X86_REG_R8,
            "IoCreateFileEx":                x86c.X86_REG_R8,
            "FltCreateCommunicationPort":    x86c.X86_REG_R8,
            "NtCreateSymbolicLinkObject":    x86c.X86_REG_R8,
        }
        interesting: Dict[int, Tuple[str, int]] = {}
        for addr, name in self.iat_map.items():
            if name in OA_APIS:
                interesting[addr] = (name, OA_APIS[name])
        if not interesting:
            return []

        VOLATILE = {x86c.X86_REG_RCX, x86c.X86_REG_RDX, x86c.X86_REG_R8,
                    x86c.X86_REG_R9, x86c.X86_REG_RAX, x86c.X86_REG_R10,
                    x86c.X86_REG_R11}
        STACK_BASES = (x86c.X86_REG_RSP, x86c.X86_REG_RBP,
                       x86c.X86_REG_ESP, x86c.X86_REG_EBP)

        def _read_ptr(va: int) -> Optional[int]:
            """Read 8-byte pointer from a VA in the image."""
            rva = va - image_base
            data = self.get_bytes_at_rva(rva, 8)
            if len(data) < 8:
                return None
            return struct.unpack_from("<Q", data, 0)[0] or None

        def _resolve_unicode_ptr(va: int) -> Optional[str]:
            """Interpret *va* as a ``UNICODE_STRING*`` and read its Buffer."""
            s = self._read_unicode_string_struct(va)
            if s:
                return s
            return self._read_wide_str(va)

        def _resolve_rdata_oa(oa_va: int) -> Optional[str]:
            """OA lives in .rdata — dereference its ObjectName field."""
            obj_name_ptr = _read_ptr(oa_va + 0x10)
            if not obj_name_ptr:
                return None
            return _resolve_unicode_ptr(obj_name_ptr)

        def _resolve_stack_oa(window, base_reg, base_disp):
            """OA built on the stack — trace the ObjectName write."""
            name_slot = base_disp + 0x10
            for idx in range(len(window) - 1, -1, -1):
                ins = window[idx]
                if ins.mnemonic != "mov" or len(ins.operands) != 2:
                    continue
                dst, src = ins.operands
                if (dst.type != x86c.X86_OP_MEM or
                        dst.mem.base != base_reg or
                        dst.mem.disp != name_slot):
                    continue
                if src.type == x86c.X86_OP_IMM and src.imm:
                    return _resolve_unicode_ptr(src.imm)
                if src.type != x86c.X86_OP_REG:
                    return None
                # Walk earlier for lea src.reg, [rip+X] or [rsp+X]
                for earlier in reversed(window[:idx]):
                    if earlier.mnemonic == "call":
                        break
                    if (earlier.mnemonic == "lea" and
                            len(earlier.operands) == 2 and
                            earlier.operands[0].type == x86c.X86_OP_REG and
                            earlier.operands[0].reg == src.reg):
                        e_src = earlier.operands[1]
                        if (e_src.type == x86c.X86_OP_MEM and
                                e_src.mem.index == 0):
                            if e_src.mem.base == x86c.X86_REG_RIP:
                                us_va = (earlier.address + earlier.size +
                                         e_src.mem.disp)
                                return _resolve_unicode_ptr(us_va)
                            if e_src.mem.base in STACK_BASES:
                                us_disp = e_src.mem.disp
                                # UNICODE_STRING on stack — find Buffer write
                                # at us_disp+8 within remaining window
                                buf_off = us_disp + 8
                                for b_idx in range(len(window) - 1, -1, -1):
                                    b = window[b_idx]
                                    if (b.mnemonic == "mov" and
                                            len(b.operands) == 2):
                                        bdst, bsrc = b.operands
                                        if (bdst.type == x86c.X86_OP_MEM and
                                                bdst.mem.base == e_src.mem.base and
                                                bdst.mem.disp == buf_off and
                                                bsrc.type == x86c.X86_OP_REG):
                                            for ee in reversed(window[:b_idx]):
                                                if ee.mnemonic == "call":
                                                    break
                                                if (ee.mnemonic == "lea" and
                                                        len(ee.operands) == 2 and
                                                        ee.operands[0].type == x86c.X86_OP_REG and
                                                        ee.operands[0].reg == bsrc.reg):
                                                    ee_src = ee.operands[1]
                                                    if (ee_src.type == x86c.X86_OP_MEM and
                                                            ee_src.mem.base == x86c.X86_REG_RIP and
                                                            ee_src.mem.index == 0):
                                                        return self._read_wide_str(
                                                            ee.address + ee.size +
                                                            ee_src.mem.disp)
                                            return None
                                return None
                return None
            return None

        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=20000)

            for i, insn in enumerate(insns):
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                target: Optional[int] = None
                if op.type == x86c.X86_OP_IMM:
                    target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    target = insn.address + insn.size + op.mem.disp
                if target not in interesting:
                    continue

                api_name, slot_reg = interesting[target]

                # Back-track to resolve the OA-pointer arg
                reg_rip: Dict[int, int] = {}
                reg_stack: Dict[int, Tuple[int, int]] = {}
                blocked: set = set()
                lo = max(0, i - 40)
                for prev in reversed(insns[lo:i]):
                    if prev.mnemonic == "call":
                        blocked |= VOLATILE
                        continue
                    if prev.mnemonic != "lea" or len(prev.operands) != 2:
                        continue
                    dst = prev.operands[0]
                    src = prev.operands[1]
                    if (dst.type != x86c.X86_OP_REG or
                            dst.reg in blocked or
                            src.type != x86c.X86_OP_MEM or
                            src.mem.index != 0):
                        continue
                    if src.mem.base == x86c.X86_REG_RIP:
                        va = prev.address + prev.size + src.mem.disp
                        reg_rip.setdefault(dst.reg, va)
                    elif src.mem.base in STACK_BASES:
                        reg_stack.setdefault(dst.reg, (src.mem.base, src.mem.disp))

                resolved: Optional[str] = None
                if slot_reg in reg_rip:
                    resolved = _resolve_rdata_oa(reg_rip[slot_reg])
                elif slot_reg in reg_stack:
                    base_reg, base_disp = reg_stack[slot_reg]
                    resolved = _resolve_stack_oa(insns[lo:i], base_reg, base_disp)

                if not resolved:
                    continue
                # Keep anything that looks like a namespace path — not just
                # \Device\, since OA-taking APIs also reach registry keys
                # (\Registry\...) and file paths (\??\C:\foo).
                if len(resolved) < 3 or not resolved.startswith("\\"):
                    continue
                if resolved.startswith("\\Registry\\"):
                    # Registry keys are useful as references but not
                    # device names — feed to registry_refs instead.
                    key = f"Registry:{resolved}"
                    if key not in seen:
                        seen.add(key)
                        results.append(key)
                    continue
                if api_name == "FltCreateCommunicationPort":
                    # Minifilter ALPC port name — not a device, but the
                    # minifilter's user-mode entry point. Tag so the caller
                    # can route it to a dedicated minifilter_ports list.
                    key = f"Port:{resolved}"
                    if key not in seen:
                        seen.add(key)
                        results.append(key)
                    continue
                if resolved not in seen:
                    seen.add(resolved)
                    results.append(resolved)

        return results

    # Well-known OS device/filesystem names. A driver referencing these is
    # almost always a CONSUMER of the OS device (opens it, queries it), not
    # the owner — so synthesizing a ``\DosDevices\Foo`` mate for them would
    # produce false positives.
    _OS_DEVICE_BLOCKLIST = frozenset({
        # Storage
        "Harddisk", "HarddiskVolume", "HarddiskDmVolumes",
        "CdRom", "CdRom0", "CdRom1", "Floppy", "Floppy0",
        "PhysicalMemory", "PhysicalDrive",
        "RawDisk", "VolMgrControl", "Volmgr", "Partmgr",
        # Network
        "Afd", "Tcp", "Tcp6", "Udp", "Udp6", "Ip", "Ip6",
        "IPMULTICAST", "RawIp", "Nsi", "Netbt",
        "LanmanRedirector", "LanmanServer", "Mup", "WebDavRedirector",
        "MRxNfs", "CdmRedirector", "RdpDr", "HGFS", "hgfs", "pfmfs",
        # IPC / pipes
        "NamedPipe", "MailSlot", "Null", "Console",
        # HID / input
        "KeyboardClass0", "KeyboardClass1",
        "MouseClass0", "MouseClass1",
        "Beep", "Serial0", "Serial1",
        # Security / api
        "KsecDD", "DeviceApi", "Dfs",
        # Misc
        "USBPDO-0",
    })

    def infer_symlink_pairs(self) -> List[str]:
        """Synthesize the matching half of each device/symlink pair when the
        driver imports ``IoCreateSymbolicLink`` (or an equivalent) but only
        one side of the pair was recovered.

        Returns bare names (no tag) — consumers should treat them as lower-
        confidence candidates. The cli keeps them in ``inferred_names`` to
        avoid polluting downstream consumers that do prefix/tail math on
        ``device_names``. Filters out well-known OS device names (Harddisk,
        Afd, NamedPipe, PhysicalMemory, …) that the driver is almost
        certainly only a consumer of.
        """
        imported = set(self.iat_map.values())
        has_symlink_api = bool(imported & {
            "IoCreateSymbolicLink",
            "IoCreateUnprotectedSymbolicLink",
            "IoDeleteSymbolicLink",
            "ZwCreateSymbolicLinkObject",
            "NtCreateSymbolicLinkObject",
            "ZwOpenSymbolicLinkObject",
            "NtOpenSymbolicLinkObject",
            "WdfDeviceCreateSymbolicLink",
        })
        if not has_symlink_api:
            return []

        existing = set(self.device_names)
        new_names: List[str] = []
        # Only match "plain" names — alphanumeric, not templates/guids/refs.
        OK_CHARS = set("abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "0123456789_-.{}")

        def _is_simple(tail: str) -> bool:
            if not tail or not (2 <= len(tail) <= 64):
                return False
            if not all(ch in OK_CHARS for ch in tail):
                return False
            if tail in self._OS_DEVICE_BLOCKLIST:
                return False
            return True

        for n in list(self.device_names):
            if ("%" in n or "<" in n or
                    n.startswith("Registry:") or
                    n.startswith("RegistryValue:") or
                    n.startswith("DeviceInterface:") or
                    n.startswith("\\FileSystem\\") or
                    n.startswith("\\Callback\\") or
                    n.startswith("\\BaseNamedObjects\\")):
                continue
            if n.startswith("\\Device\\"):
                tail = n[len("\\Device\\"):]
                if not _is_simple(tail):
                    continue
                if (f"\\DosDevices\\{tail}" not in existing and
                        f"\\??\\{tail}" not in existing):
                    mate = f"\\DosDevices\\{tail}"
                    if mate not in new_names:
                        new_names.append(mate)
            elif n.startswith("\\DosDevices\\"):
                tail = n[len("\\DosDevices\\"):]
                if not _is_simple(tail):
                    continue
                if f"\\Device\\{tail}" not in existing:
                    mate = f"\\Device\\{tail}"
                    if mate not in new_names:
                        new_names.append(mate)
            elif n.startswith("\\??\\"):
                tail = n[len("\\??\\"):]
                if not _is_simple(tail):
                    continue
                if f"\\Device\\{tail}" not in existing:
                    mate = f"\\Device\\{tail}"
                    if mate not in new_names:
                        new_names.append(mate)

        return new_names

    def extract_guid_interface_structs(self, dis: "Disassembler") -> List[str]:
        """Resolve device interface class GUIDs that are stored as raw
        16-byte GUID structs in ``.rdata`` (not as ``{...}`` string form).

        At each call to ``IoRegisterDeviceInterface`` /
        ``IoOpenDeviceInterfaceRegistryKey`` / ``IoGetDeviceInterfaces`` /
        ``WdfDeviceCreateDeviceInterface`` we back-track ``lea rdx, [rip+X]``
        and read 16 bytes at X, formatting as a GUID string. Returned as
        ``DeviceInterface:{GUID}`` entries so they dedupe against the
        string-GUID path already used by ``_find_device_names``.
        """
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        results: List[str] = []
        seen: set = set()

        GUID_APIS = {
            "IoRegisterDeviceInterface",
            "IoOpenDeviceInterfaceRegistryKey",
            "IoGetDeviceInterfaces",
            "IoGetDeviceInterfaceAlias",
            "IoSetDeviceInterfaceState",
            "WdfDeviceCreateDeviceInterface",
        }
        interesting: Dict[int, str] = {
            addr: name for addr, name in self.iat_map.items()
            if name in GUID_APIS
        }
        if not interesting:
            return []

        VOLATILE = (x86c.X86_REG_RCX, x86c.X86_REG_RDX, x86c.X86_REG_R8,
                    x86c.X86_REG_R9, x86c.X86_REG_RAX, x86c.X86_REG_R10,
                    x86c.X86_REG_R11)

        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=20000)

            for i, insn in enumerate(insns):
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                target: Optional[int] = None
                if op.type == x86c.X86_OP_IMM:
                    target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    target = insn.address + insn.size + op.mem.disp
                if target not in interesting:
                    continue

                # Back-track lea rdx, [rip+X] (2nd arg = InterfaceClassGuid*)
                rdx_va: Optional[int] = None
                for prev in reversed(insns[max(0, i - 30): i]):
                    if prev.mnemonic == "call":
                        # rdx is volatile — clobbered
                        break
                    if (prev.mnemonic == "lea" and len(prev.operands) == 2 and
                            prev.operands[0].type == x86c.X86_OP_REG and
                            prev.operands[0].reg in (x86c.X86_REG_RDX,
                                                      x86c.X86_REG_EDX)):
                        src = prev.operands[1]
                        if (src.type == x86c.X86_OP_MEM and
                                src.mem.base == x86c.X86_REG_RIP and
                                src.mem.index == 0):
                            rdx_va = prev.address + prev.size + src.mem.disp
                            break

                if not rdx_va:
                    continue

                guid = self._read_guid_struct(rdx_va)
                if not guid:
                    continue
                label = f"DeviceInterface:{guid}"
                if label not in seen:
                    seen.add(label)
                    results.append(label)

        return results

    def extract_guid_immediate_stores(self, dis: "Disassembler") -> List[str]:
        """Recover device interface class GUIDs that are built on the stack
        via a sequence of ``mov [rsp+N], imm`` stores, then passed by
        ``lea rdx, [rsp+N]`` to an ``Io*DeviceInterface*`` /
        ``WdfDeviceCreateDeviceInterface`` call.

        Typical MSVC output for a literal ``GUID`` local::

            mov     dword ptr [rsp+30h], 0AABBCCDDh       ; Data1
            mov     word  ptr [rsp+34h], 1122h            ; Data2
            mov     word  ptr [rsp+36h], 3344h            ; Data3
            mov     qword ptr [rsp+38h], 0F0E0D0C0B0A0908h ; Data4[8]
            lea     rdx, [rsp+30h]
            call    cs:IoRegisterDeviceInterface

        Collects 16 contiguous bytes from such stores and formats as the
        ``{XXXXXXXX-XXXX-...}`` GUID string. De-duplicates against the
        results already yielded by ``extract_guid_interface_structs``.
        """
        results: List[str] = []
        seen: set = set()

        GUID_APIS = {
            "IoRegisterDeviceInterface",
            "IoOpenDeviceInterfaceRegistryKey",
            "IoGetDeviceInterfaces",
            "IoGetDeviceInterfaceAlias",
            "IoSetDeviceInterfaceState",
            "WdfDeviceCreateDeviceInterface",
        }
        interesting: Dict[int, str] = {
            addr: name for addr, name in self.iat_map.items()
            if name in GUID_APIS
        }
        if not interesting:
            return []

        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        SIZE_MAP = {1: "B", 2: "H", 4: "I", 8: "Q"}

        for sec in self.pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            sec_va   = image_base + sec.VirtualAddress
            sec_data = sec.get_data()
            insns    = dis.disassemble_range(sec_data, sec_va, max_insns=20000)

            for i, insn in enumerate(insns):
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                target: Optional[int] = None
                if op.type == x86c.X86_OP_IMM:
                    target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    target = insn.address + insn.size + op.mem.disp
                if target not in interesting:
                    continue

                # Back-track lea rdx, [rsp+N] (or [rbp-N]) — stack GUID.
                rdx_base: Optional[int] = None
                rdx_off:  Optional[int] = None
                lea_idx:  int = i
                window_start = max(0, i - 80)
                for j in range(i - 1, window_start - 1, -1):
                    prev = insns[j]
                    if prev.mnemonic == "call":
                        break
                    if (prev.mnemonic == "lea" and len(prev.operands) == 2 and
                            prev.operands[0].type == x86c.X86_OP_REG and
                            prev.operands[0].reg in (x86c.X86_REG_RDX,
                                                      x86c.X86_REG_EDX)):
                        src = prev.operands[1]
                        if (src.type == x86c.X86_OP_MEM and
                                src.mem.base in (x86c.X86_REG_RSP,
                                                  x86c.X86_REG_RBP) and
                                src.mem.index == 0):
                            rdx_base = src.mem.base
                            rdx_off  = src.mem.disp
                            lea_idx  = j
                            break
                if rdx_base is None:
                    continue

                # Collect [rsp+rdx_off .. rdx_off+15] bytes from prior
                # mov-imm stores. Walk backward from the lea; stop at the
                # start of the basic block (first branch/call/ret before it
                # that'd clobber the stack slots).
                guid_bytes = bytearray(b"\x00" * 16)
                covered    = [False] * 16
                for prev in reversed(insns[window_start: lea_idx]):
                    if prev.mnemonic in ("call", "jmp", "ret", "retf"):
                        break
                    if prev.mnemonic != "mov" or len(prev.operands) != 2:
                        continue
                    dst, src = prev.operands
                    if src.type != x86c.X86_OP_IMM:
                        continue
                    if (dst.type != x86c.X86_OP_MEM or
                            dst.mem.base != rdx_base or
                            dst.mem.index != 0):
                        continue
                    sz = dst.size
                    if sz not in SIZE_MAP:
                        continue
                    rel = dst.mem.disp - rdx_off
                    if rel < 0 or rel + sz > 16:
                        continue
                    # Don't overwrite bytes already filled by a later store
                    # (later in program order = encountered first, since
                    # we're iterating backward).
                    if any(covered[rel + k] for k in range(sz)):
                        continue
                    try:
                        packed = struct.pack("<" + SIZE_MAP[sz],
                                              src.imm & ((1 << (sz * 8)) - 1))
                    except Exception:
                        continue
                    guid_bytes[rel: rel + sz] = packed
                    for k in range(sz):
                        covered[rel + k] = True
                    if all(covered):
                        break

                if not all(covered):
                    continue
                try:
                    d1, d2, d3 = struct.unpack_from("<IHH", guid_bytes, 0)
                    d4 = bytes(guid_bytes[8:16])
                except Exception:
                    continue
                # Sanity: reject all-zero / all-0xFF
                if d1 == 0 and d2 == 0 and d3 == 0 and all(b == 0 for b in d4):
                    continue
                if (d1 == 0xFFFFFFFF and d2 == 0xFFFF and d3 == 0xFFFF and
                        all(b == 0xFF for b in d4)):
                    continue
                guid = ("{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-"
                        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}").format(
                            d1, d2, d3, d4[0], d4[1],
                            d4[2], d4[3], d4[4], d4[5], d4[6], d4[7])
                label = f"DeviceInterface:{guid}"
                if label not in seen:
                    seen.add(label)
                    results.append(label)

        return results
