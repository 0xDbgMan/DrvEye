"""Certificate and load compatibility scanning."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from drivertool.constants import (
    KERNEL_TRUSTED_ROOTS, KNOWN_REVOKED_CERTS,
    LIVE_BLOCKED_DRIVER_HASHES_SHA1, LIVE_BLOCKED_DRIVER_HASHES_SHA256,
    LIVE_DISALLOWED_THUMBPRINTS, LIVE_DISALLOWED_THUMBPRINTS_SHA256,
    LOLDRIVERS_HASHES, MS_DRIVER_BLOCKLIST, SUSPICIOUS_SIGNERS, Severity,
)
from drivertool.models import Finding

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class CertScanMixin:
    """Mixin for certificate and load-compatibility scans."""

    def scan_certificate(self):
        """
        Validate the driver's Authenticode signature and certificate chain.
        Checks: presence, expiry, self-signed, key strength, known-revoked,
        suspicious signers, test certs, cross-signing, and code-signing EKU.
        """
        ci = self.pe.cert_info
        if not ci:
            return

        # ── 1. No signature at all ─────────────────────────────────────────
        if not ci.get("signed"):
            likely_cat = ci.get("likely_catalog_signed", False)
            cat_reason = ci.get("catalog_sign_reason", "")
            if likely_cat:
                self.findings.append(Finding(
                    title="No embedded signature — likely catalog-signed (external .cat)",
                    severity=Severity.INFO,
                    description=f"{cat_reason}. The driver has no embedded "
                                "Authenticode signature in its PE security "
                                "directory, but its version info + PE "
                                "characteristics indicate a Microsoft-shipped "
                                "driver that relies on an external catalog "
                                "(.cat) signature. Catalog-signed drivers "
                                "load on Windows provided the matching "
                                "catalog is registered (all shipped drivers "
                                "have their cats registered by the OS). "
                                "Cannot verify the catalog standalone.",
                    location="PE Security Directory",
                ))
            else:
                self.findings.append(Finding(
                    title="Driver is NOT digitally signed",
                    severity=Severity.CRITICAL,
                    description="No Authenticode signature found in the PE security directory. "
                                "Since Windows 10 1607+, kernel drivers must be signed by "
                                "Microsoft or have a valid cross-signed certificate. An unsigned "
                                "driver can only load with test-signing or Secure Boot disabled.",
                    location="PE Security Directory",
                ))
            return

        self.findings.append(Finding(
            title="Driver has Authenticode signature",
            severity=Severity.INFO,
            description="PE contains a WIN_CERTIFICATE structure with embedded signature.",
            location="PE Security Directory",
            details={"revision": ci.get("win_cert_revision", ""),
                     "cert_count": str(ci.get("cert_count", 0))},
        ))

        if ci.get("parse_error"):
            self.findings.append(Finding(
                title="Certificate parsing error",
                severity=Severity.LOW,
                description=f"Could not fully parse certificate: {ci['parse_error']}",
                location="PE Security Directory",
            ))
            return

        signer_cn = ci.get("signer_cn", "")
        signer_org = ci.get("signer_org", "")
        signer_serial = ci.get("signer_serial", "")
        signer_issuer = ci.get("signer_issuer", "")

        # Report signer identity
        if signer_cn:
            self.findings.append(Finding(
                title=f"Signed by: {signer_cn}",
                severity=Severity.INFO,
                description=f"Subject: {signer_cn} ({signer_org})\n"
                            f"Issuer: {signer_issuer}\n"
                            f"Serial: {signer_serial}\n"
                            f"Key: {ci.get('signer_key_type', '?')} "
                            f"{ci.get('signer_key_size', '?')}-bit\n"
                            f"Valid until: {ci.get('signer_not_after', '?')}",
                location="Authenticode Certificate",
                details={
                    "signer_cn": signer_cn,
                    "signer_org": signer_org,
                    "issuer": signer_issuer,
                    "serial": signer_serial,
                    "thumbprint": ci.get("signer_thumbprint", ""),
                },
            ))

        # ── 2. Expired certificate ─────────────────────────────────────────
        if ci.get("signer_expired"):
            self.findings.append(Finding(
                title=f"Signing certificate EXPIRED (valid until {ci.get('signer_not_after', '?')})",
                severity=Severity.HIGH,
                description="The code-signing certificate has expired. While drivers with "
                            "a valid timestamp counter-signature remain valid after expiry, "
                            "an expired cert without a timestamp means the signature is no "
                            "longer trusted. This is also common in BYOVD — old vulnerable "
                            "drivers with expired certs that were signed before revocation.",
                location="Authenticode Certificate",
                details={"not_after": ci.get("signer_not_after", "")},
            ))

        # ── 3. Self-signed certificate ─────────────────────────────────────
        if ci.get("signer_self_signed"):
            self.findings.append(Finding(
                title="Driver signed with SELF-SIGNED certificate",
                severity=Severity.CRITICAL,
                description="The signing certificate is self-signed (issuer == subject). "
                            "Self-signed drivers have no trust chain and cannot be verified "
                            "by the OS certificate store. This requires test-signing mode "
                            "to be enabled, which is a significant security downgrade. "
                            "Malware often uses self-signed certs.",
                location="Authenticode Certificate",
                details={"signer_cn": signer_cn},
            ))

        # ── 4. Weak key ────────────────────────────────────────────────────
        key_size = ci.get("signer_key_size", 0)
        key_type = ci.get("signer_key_type", "")
        if key_type == "RSA" and 0 < key_size < 2048:
            self.findings.append(Finding(
                title=f"Weak RSA key: {key_size}-bit",
                severity=Severity.HIGH,
                description=f"The signing certificate uses a {key_size}-bit RSA key. "
                            f"Keys shorter than 2048 bits are considered weak and may be "
                            f"factored. Microsoft requires at least 2048-bit RSA for "
                            f"code signing since 2016.",
                location="Authenticode Certificate",
                details={"key_type": key_type, "key_size": str(key_size)},
            ))
        elif key_type == "EC" and 0 < key_size < 256:
            self.findings.append(Finding(
                title=f"Weak EC key: {key_size}-bit",
                severity=Severity.HIGH,
                description=f"The signing certificate uses a {key_size}-bit EC key. "
                            f"EC keys shorter than 256 bits are considered weak.",
                location="Authenticode Certificate",
            ))

        # ── 5. Known-revoked certificate serial match ──────────────────────
        serial_lower = signer_serial.lower().lstrip("0") if signer_serial else ""
        for revoked_serial, revoked_desc in KNOWN_REVOKED_CERTS.items():
            norm_revoked = revoked_serial.lower().lstrip("0")
            if serial_lower and serial_lower == norm_revoked:
                self.findings.append(Finding(
                    title=f"REVOKED certificate: {revoked_desc}",
                    severity=Severity.CRITICAL,
                    description=f"The signing certificate serial number ({signer_serial}) "
                                f"matches a known revoked/compromised certificate: "
                                f"{revoked_desc}. This driver should NOT be trusted.",
                    location="Authenticode Certificate",
                    details={"serial": signer_serial, "revoked_info": revoked_desc},
                ))
                break

        # Also check all certs in the chain (intermediate certs can be revoked too)
        for cert_entry in ci.get("certificates", []):
            c_serial = cert_entry.get("serial", "").lower().lstrip("0")
            if c_serial == serial_lower:
                continue  # Already checked signer
            for revoked_serial, revoked_desc in KNOWN_REVOKED_CERTS.items():
                if c_serial and c_serial == revoked_serial.lower().lstrip("0"):
                    self.findings.append(Finding(
                        title=f"Chain contains REVOKED certificate: {revoked_desc}",
                        severity=Severity.CRITICAL,
                        description=f"A certificate in the signing chain has serial "
                                    f"({cert_entry['serial']}) matching a known revoked cert: "
                                    f"{revoked_desc}.",
                        location="Certificate Chain",
                        details={"serial": cert_entry["serial"],
                                 "subject": cert_entry.get("subject_cn", "")},
                    ))
                    break

        # ── 6. Suspicious signer name ──────────────────────────────────────
        check_names = (signer_cn + " " + signer_org).lower()
        for pattern, reason in SUSPICIOUS_SIGNERS:
            if pattern in check_names:
                self.findings.append(Finding(
                    title=f"Suspicious signer: {reason}",
                    severity=Severity.HIGH,
                    description=f"The signer name '{signer_cn}' / '{signer_org}' matches "
                                f"suspicious pattern: {reason}.",
                    location="Authenticode Certificate",
                    details={"signer_cn": signer_cn, "pattern": pattern},
                ))
                break  # One match is enough

        # ── 7. Missing code-signing EKU ────────────────────────────────────
        # The signer cert should have codeSigning EKU
        signer_cert_data = None
        for c in ci.get("certificates", []):
            if not c.get("is_ca") and c.get("subject_cn") == signer_cn:
                signer_cert_data = c
                break
        if not signer_cert_data:
            signer_cert_data = ci.get("certificates", [{}])[0] if ci.get("certificates") else {}

        if signer_cert_data and signer_cert_data.get("eku"):
            if not signer_cert_data.get("has_code_signing_eku"):
                self.findings.append(Finding(
                    title="Signer certificate lacks Code Signing EKU",
                    severity=Severity.HIGH,
                    description="The signing certificate has Extended Key Usage extensions "
                                "but does NOT include codeSigning (1.3.6.1.5.5.7.3.3). "
                                "This certificate was not intended for code signing. "
                                "Some older drivers were signed with mismatched EKU certs.",
                    location="Authenticode Certificate",
                    details={"eku": str(signer_cert_data.get("eku", []))},
                ))

        # ── 8. Certificate chain depth ─────────────────────────────────────
        cert_count = ci.get("cert_count", 0)
        if cert_count == 1 and not ci.get("signer_self_signed"):
            self.findings.append(Finding(
                title="Incomplete certificate chain (single cert, no intermediates)",
                severity=Severity.MEDIUM,
                description="Only one certificate is embedded in the signature. "
                            "A proper Authenticode signature should include the full "
                            "chain (signer → intermediate CA → root). Missing intermediates "
                            "may prevent offline verification.",
                location="Authenticode Certificate",
                details={"cert_count": str(cert_count)},
            ))

        # ── 9. Cross-signing check (important for kernel drivers) ──────────
        # After 2021-07, new kernel drivers must be submitted to Microsoft's
        # Hardware Dev Center. Older drivers used cross-signing. Check if the
        # issuer chain goes through Microsoft.
        has_ms_in_chain = False
        for c in ci.get("certificates", []):
            name_lower = (c.get("issuer_cn", "") + c.get("subject_cn", "")).lower()
            if "microsoft" in name_lower:
                has_ms_in_chain = True
                break
        if not has_ms_in_chain and not ci.get("signer_self_signed"):
            self.findings.append(Finding(
                title="No Microsoft certificate in signing chain",
                severity=Severity.MEDIUM,
                description="The certificate chain does not include any Microsoft-issued "
                            "certificate. Since July 2021, new kernel-mode drivers must be "
                            "submitted to Microsoft's Hardware Dev Center portal for signing. "
                            "Drivers without Microsoft in the chain are either legacy "
                            "(pre-2021), cross-signed with a now-expired cert, or test-signed.",
                location="Certificate Chain",
            ))

        # ── 10. Check all certs for expiry (intermediate/root too) ─────────
        expired_chain = []
        for c in ci.get("certificates", []):
            if c.get("expired") and c.get("subject_cn") != signer_cn:
                expired_chain.append(c.get("subject_cn", "unknown"))
        if expired_chain:
            self.findings.append(Finding(
                title=f"Expired certificates in chain: {', '.join(expired_chain)}",
                severity=Severity.MEDIUM,
                description="One or more certificates in the signing chain have expired. "
                            "If the root or intermediate CA cert has expired, the entire "
                            "chain of trust is broken unless a valid timestamp exists.",
                location="Certificate Chain",
                details={"expired_certs": expired_chain},
            ))

        # ── 11. SHA-1 signature algorithm deprecation ─────────────────────
        # Since 2020, Windows rejects SHA-1-signed drivers in many scenarios.
        # Check if any cert in the chain uses SHA-1.
        sha1_certs = []
        for c in ci.get("certificates", []):
            sig_alg = c.get("signature_algorithm", "")
            if "sha1" in sig_alg.lower() and "sha1" not in "sha1WithRSAEncryption":
                sha1_certs.append(c.get("subject_cn", "unknown"))
        # Also check via thumbprint heuristic — SHA-1 signed certs tend
        # to have certain OID patterns. For now, check signer cert.
        if signer_cert_data:
            sig_hash = signer_cert_data.get("signature_hash_algorithm", "")
            nested_modern = any(
                n.get("digest_algorithm", "").lower() in ("sha256", "sha384", "sha512")
                and n.get("signature_valid") is not False
                and n.get("pe_hash_match") is not False
                for n in (ci.get("nested_signatures") or []))
            if sig_hash and "sha1" in sig_hash.lower() and not nested_modern:
                self.findings.append(Finding(
                    title="Signing certificate uses deprecated SHA-1 algorithm",
                    severity=Severity.HIGH,
                    description="The signing certificate uses SHA-1 hash algorithm which "
                                "has been deprecated by Microsoft since 2020. SHA-1 signed "
                                "drivers may be rejected on Windows 10 1903+ and will not "
                                "pass WHQL attestation signing. SHA-256 or stronger required.",
                    location="Authenticode Certificate",
                    details={"algorithm": sig_hash},
                ))

        # ── 12. Timestamp countersignature quality ────────────────────────
        ts_signer = ci.get("timestamp_signer", "")
        if ci.get("signed") and not ts_signer:
            self.findings.append(Finding(
                title="No timestamp countersignature detected",
                severity=Severity.MEDIUM,
                description="The Authenticode signature has no countersignature timestamp. "
                            "Without a timestamp, the signature becomes invalid after the "
                            "signing certificate expires. Timestamped signatures remain "
                            "valid indefinitely. This affects driver loadability.",
                location="Authenticode Certificate",
            ))

        # ── 13. Cryptographic PKCS#7 signature verification ──────────────
        # "signed" only means a signature blob is present — it doesn't mean
        # the math holds. Windows rejects drivers whose PKCS#7 signature
        # does not verify against the signer cert's public key.
        sig_valid = ci.get("signature_valid")
        if sig_valid is False:
            self.findings.append(Finding(
                title="PKCS#7 signature failed cryptographic verification",
                severity=Severity.CRITICAL,
                description="The Authenticode signature is present but the signature "
                            "math does not verify: "
                            f"{ci.get('signature_error') or 'unknown error'}. "
                            "Windows will REFUSE to load this driver regardless of "
                            "signer identity or chain trust. This strongly suggests "
                            "post-signing tampering, a forged signature, or a "
                            "corrupted PKCS#7 blob.",
                location="Authenticode Certificate",
                details={"error": ci.get("signature_error", "")},
            ))
        elif sig_valid is True:
            self.findings.append(Finding(
                title="PKCS#7 signature verifies cryptographically",
                severity=Severity.INFO,
                description="The primary Authenticode PKCS#7 signature was verified "
                            "against the signer certificate's public key.",
                location="Authenticode Certificate",
            ))

        # ── 14. Authenticode PE hash comparison (tamper detection) ───────
        pe_match = ci.get("pe_hash_match")
        if pe_match is False:
            self.findings.append(Finding(
                title="Authenticode PE hash MISMATCH — binary tampered post-signing",
                severity=Severity.CRITICAL,
                description="The PE image's recomputed Authenticode hash "
                            f"({ci.get('pe_hash_actual', '?')[:32]}…) does not "
                            f"match the hash embedded in the signature "
                            f"({ci.get('pe_hash_expected', '?')[:32]}…). The binary "
                            "was modified after it was signed. Windows Code "
                            "Integrity will REJECT this driver — signed or not.",
                location="Authenticode Signature",
                details={
                    "algorithm": ci.get("pe_hash_algorithm", ""),
                    "expected": ci.get("pe_hash_expected", ""),
                    "actual": ci.get("pe_hash_actual", ""),
                },
            ))
        elif pe_match is True:
            self.findings.append(Finding(
                title="Authenticode PE hash matches (binary not tampered)",
                severity=Severity.INFO,
                description=f"Recomputed {ci.get('pe_hash_algorithm', '?')} hash of the "
                            "PE image matches the value embedded in SpcIndirectDataContent.",
                location="Authenticode Signature",
            ))

        # ── 15. Nested SHA-256 signature (dual-sign) ─────────────────────
        nested = ci.get("nested_signatures", []) or []
        primary_alg = ""
        sd_hash_oid = None
        # Infer primary digest algorithm from signer cert's signature hash
        signer_sig_alg = (signer_cert_data or {}).get("signature_hash_algorithm", "")
        if signer_sig_alg:
            primary_alg = signer_sig_alg.lower()
        if nested:
            algs = [n.get("digest_algorithm", "?") for n in nested]
            any_invalid = any(n.get("signature_valid") is False for n in nested)
            any_hash_bad = any(n.get("pe_hash_match") is False for n in nested)
            self.findings.append(Finding(
                title=f"Nested signature(s) present: {', '.join(algs)}",
                severity=Severity.HIGH if (any_invalid or any_hash_bad) else Severity.INFO,
                description="The primary signature is dual-signed — a second "
                            "(typically SHA-256) signature is nested via "
                            "MsSpcNestedSignature. Windows on modern Windows 10+ / "
                            "HVCI prefers the SHA-256 side for verification."
                            + (" One or more nested signatures failed "
                               "cryptographic verification or have mismatched "
                               "PE hashes — these will NOT be accepted."
                               if (any_invalid or any_hash_bad) else ""),
                location="Authenticode Signature",
                details={
                    "count": str(len(nested)),
                    "algorithms": algs,
                    "any_invalid": str(any_invalid),
                    "any_pe_hash_bad": str(any_hash_bad),
                },
            ))
        # Replace the heuristic SHA-1 deprecation behaviour: only flag if
        # the primary is SHA-1 AND no SHA-256 nested signature is present.
        nested_has_sha256 = any(
            "sha256" in (n.get("digest_algorithm", "").lower())
            or "sha384" in (n.get("digest_algorithm", "").lower())
            or "sha512" in (n.get("digest_algorithm", "").lower())
            for n in nested)
        if "sha1" in primary_alg and not nested_has_sha256:
            self.findings.append(Finding(
                title="Only SHA-1 Authenticode signature — rejected on modern Windows",
                severity=Severity.HIGH,
                description="Primary signature uses SHA-1 and no SHA-256 nested "
                            "signature is present. Windows 10 1903+ / HVCI systems "
                            "will reject this driver at load time.",
                location="Authenticode Signature",
            ))

        # ── 16. Kernel-trusted root anchoring ────────────────────────────
        anchor = ci.get("chain_anchor") or {}
        kind = anchor.get("kind", "unknown")
        trusted = anchor.get("trusted_for_kernel", False)
        if kind == "no-ms-root":
            self.findings.append(Finding(
                title="Chain does not terminate at a Windows kernel-trusted root",
                severity=Severity.HIGH,
                description="The certificate chain does not chain up to any root "
                            "present in the Windows kernel trust store "
                            f"({len(KERNEL_TRUSTED_ROOTS)} known roots checked by "
                            "thumbprint). Unless a missing intermediate can be "
                            "supplied by the OS at load time, Windows will not "
                            "accept this driver.",
                location="Certificate Chain",
                details={"anchor_kind": kind},
            ))
        elif kind == "embedded-self-root" and not trusted:
            self.findings.append(Finding(
                title="Chain terminates at a self-signed root — not kernel-trusted",
                severity=Severity.HIGH,
                description=f"Chain anchor is '{anchor.get('matched_name', '')}', "
                            "a self-signed CA not present in the Windows kernel "
                            "trust store. Requires test-signing mode to load.",
                location="Certificate Chain",
                details=anchor,
            ))
        elif trusted:
            self.findings.append(Finding(
                title=f"Chain anchored to kernel-trusted root ({kind})",
                severity=Severity.INFO,
                description=f"Chain terminates at '{anchor.get('matched_name', '')}' "
                            f"— recognised as kernel-trusted ({kind}).",
                location="Certificate Chain",
                details=anchor,
            ))

    def scan_load_compatibility(self):
        """
        Assess whether this driver can actually load on modern Windows.
        Checks: architecture, signing policy, Secure Boot, HVCI, MS block list,
        cross-signing expiry, test-signing, and driver service requirements.
        """
        ci = self.pe.cert_info
        sf = getattr(self.pe, "security_flags", {})
        is_64 = self.pe.is_64bit

        load_status = []   # (can_load: bool, condition: str, detail: str)
        blocked = False

        # ── 1. Microsoft Vulnerable Driver Block List ──────────────────────
        sha = self.pe.file_hash
        sha1 = getattr(self.pe, "file_hash_sha1", "")

        if sha in MS_DRIVER_BLOCKLIST:
            blocked = True
            desc = MS_DRIVER_BLOCKLIST[sha]
            self.findings.append(Finding(
                title=f"BLOCKED by Microsoft Driver Block List: {desc}",
                severity=Severity.CRITICAL,
                description=f"This driver's SHA-256 ({sha[:16]}...) is on Microsoft's "
                            f"Vulnerable Driver Block List (DriverSiPolicy). Windows will "
                            f"REFUSE to load this driver when Secure Boot is enabled or "
                            f"HVCI (Memory Integrity) is active. Block reason: {desc}",
                location="SHA-256 hash",
                details={"sha256": sha, "block_entry": desc},
            ))
            load_status.append((False, "MS Block List", desc))
        else:
            # Build the set of hashes that WDAC could match this driver on:
            # flat file SHA-1/SHA-256 and every Authenticode PE hash we have
            # (primary + nested signatures, typically SHA-1 + SHA-256).
            candidate_sha1 = {sha1.lower()} if sha1 else set()
            candidate_sha256 = {sha.lower()}
            auth_actual = (ci.get("pe_hash_actual") or "").lower()
            auth_alg    = (ci.get("pe_hash_algorithm") or "").lower()
            if auth_actual:
                if auth_alg == "sha1":
                    candidate_sha1.add(auth_actual)
                elif auth_alg == "sha256":
                    candidate_sha256.add(auth_actual)
            for n in (ci.get("nested_signatures") or []):
                na = (n.get("pe_hash_actual") or "").lower()
                nalg = (n.get("pe_hash_algorithm") or "").lower()
                if not na:
                    continue
                if nalg == "sha1":
                    candidate_sha1.add(na)
                elif nalg == "sha256":
                    candidate_sha256.add(na)

            hit1 = candidate_sha1 & LIVE_BLOCKED_DRIVER_HASHES_SHA1
            hit2 = candidate_sha256 & LIVE_BLOCKED_DRIVER_HASHES_SHA256
            if hit1 or hit2:
                blocked = True
                matched = next(iter(hit2 or hit1))
                alg = "SHA-256" if hit2 else "SHA-1"
                self.findings.append(Finding(
                    title="BLOCKED by live Microsoft Driver Block List",
                    severity=Severity.CRITICAL,
                    description=f"This driver's {alg} hash ({matched[:16]}...) "
                                f"matches an entry in the currently-published "
                                f"Microsoft vulnerable-driver block list "
                                f"(SiPolicy_Enforced.p7b). Windows with "
                                f"Secure Boot, HVCI, or Smart App Control "
                                f"will REFUSE to load this driver.",
                    location="Live WDAC Block List",
                    details={"matched_hash": matched, "algorithm": alg},
                ))
                load_status.append((False, "MS Block List (live)",
                                     f"Matches live WDAC blocklist {alg} hash"))

        # Also check LOLDRIVERS
        if sha in LOLDRIVERS_HASHES:
            desc = LOLDRIVERS_HASHES[sha]
            self.findings.append(Finding(
                title=f"Known vulnerable driver (LOLDrivers): {desc}",
                severity=Severity.CRITICAL,
                description=f"This driver is listed in the LOLDrivers database as a known "
                            f"vulnerable/abused driver: {desc}. It may be blocked by "
                            f"EDR/AV solutions and Microsoft Defender.",
                location="SHA-256 hash",
                details={"sha256": sha, "loldrivers_entry": desc},
            ))

        # ── 2. Signature status → loading policy ──────────────────────────
        is_signed = ci.get("signed", False)
        is_self_signed = ci.get("signer_self_signed", False)
        is_expired = ci.get("signer_expired", False)
        # Prefer the thumbprint-anchored verdict over CN substring heuristics.
        anchor_ci = ci.get("chain_anchor") or {}
        has_ms_chain = anchor_ci.get("kind") in ("ms-kernel", "ms-root-referenced",
                                                 "cross-sign")
        if not has_ms_chain:
            # Back-compat fallback
            for c in ci.get("certificates", []):
                if "microsoft" in (c.get("issuer_cn", "") + c.get("subject_cn", "")).lower():
                    has_ms_chain = True
                    break

        # ── 2a. Cryptographic signature verdict (overrides optimistic "signed") ──
        sig_valid = ci.get("signature_valid")
        pe_hash_match = ci.get("pe_hash_match")
        nested = ci.get("nested_signatures", []) or []
        any_nested_ok = any(
            n.get("signature_valid") is True and n.get("pe_hash_match") is not False
            for n in nested)
        # If primary fails crypto but a nested sig succeeds, Windows still loads.
        effectively_verified = (
            (sig_valid is True and pe_hash_match is not False) or any_nested_ok)

        if is_signed and sig_valid is False and not any_nested_ok:
            load_status.append((False, "Signature Crypto",
                                f"PKCS#7 signature failed to verify: "
                                f"{ci.get('signature_error', 'unknown')}"))
        elif is_signed and pe_hash_match is False and not any_nested_ok:
            load_status.append((False, "PE Hash",
                                "Authenticode PE hash mismatch — binary was modified "
                                "after signing"))

        # ── 2b. Kernel-trusted root anchoring ────────────────────────────
        anchor = ci.get("chain_anchor") or {}
        if is_signed and not anchor.get("trusted_for_kernel", False):
            load_status.append((False, "Kernel Trust Anchor",
                                f"Chain does not terminate at a Windows kernel "
                                f"trust root ({anchor.get('kind', 'unknown')})"))

        if not is_signed:
            load_status.append((False, "No Signature",
                                "Unsigned drivers cannot load on Win10+ with Secure Boot"))
            self.findings.append(Finding(
                title="Load blocked: Driver is unsigned",
                severity=Severity.CRITICAL,
                description="Windows 10 (1607+) requires all kernel drivers to have a "
                            "valid Authenticode signature. An unsigned driver will only "
                            "load if test-signing mode is enabled via "
                            "'bcdedit /set testsigning on', which disables Secure Boot.",
                location="Signature Policy",
            ))
        elif is_self_signed:
            load_status.append((False, "Self-Signed",
                                "Self-signed drivers require test-signing mode"))
            self.findings.append(Finding(
                title="Load restricted: Self-signed certificate",
                severity=Severity.HIGH,
                description="This driver is self-signed. It will only load on Windows "
                            "with test-signing mode enabled (bcdedit /set testsigning on). "
                            "A watermark appears on the desktop when test-signing is active.",
                location="Signature Policy",
            ))
        elif is_expired and not ci.get("timestamp_signer"):
            load_status.append((False, "Expired + No Timestamp",
                                "Expired cert without countersignature timestamp"))
            self.findings.append(Finding(
                title="Load may fail: Expired certificate without timestamp",
                severity=Severity.HIGH,
                description="The signing certificate has expired and no countersignature "
                            "timestamp was detected. Without a timestamp proving the driver "
                            "was signed before expiry, Windows may reject the signature.",
                location="Signature Policy",
            ))
        elif is_expired and ci.get("timestamp_signer"):
            load_status.append((True, "Expired + Timestamped",
                                "Expired cert but has valid timestamp — signature accepted"))
        elif has_ms_chain:
            load_status.append((True, "Microsoft-Signed Chain",
                                "Certificate chain includes Microsoft — full trust"))
        elif is_signed:
            load_status.append((True, "Third-Party Signed",
                                "Signed by third-party CA — may need cross-signing for kernel"))

        # ── 3. Cross-signing expiry (pre-2021 kernel drivers) ─────────────
        # Microsoft stopped accepting new cross-signed drivers on July 1, 2021.
        # Existing cross-signed drivers still work if timestamp is before expiry.
        if is_signed and not has_ms_chain and not is_self_signed:
            # Check if the cross-signing root cert in chain has expired
            for c in ci.get("certificates", []):
                if c.get("is_ca") and c.get("expired"):
                    issuer = c.get("issuer_cn", "")
                    if "microsoft" in issuer.lower():
                        self.findings.append(Finding(
                            title="Cross-signing CA certificate expired",
                            severity=Severity.MEDIUM,
                            description=f"The cross-signing CA certificate "
                                        f"'{c.get('subject_cn', '?')}' (issued by {issuer}) "
                                        f"expired on {c.get('not_after', '?')[:10]}. "
                                        f"The driver signature is still valid IF a "
                                        f"countersignature timestamp proves it was signed "
                                        f"before the CA expiry date.",
                            location="Certificate Chain",
                        ))
                        break

        # ── 4. HVCI (Memory Integrity) compatibility ──────────────────────
        force_integrity = sf.get("FORCE_INTEGRITY", False)
        has_wx = any(s["writable"] and s["executable"] for s in self.pe.sections)
        hvci_ok = force_integrity and not has_wx

        if not hvci_ok:
            reasons = []
            if not force_integrity:
                reasons.append("missing FORCE_INTEGRITY flag")
            if has_wx:
                reasons.append("has W+X sections")
            self.findings.append(Finding(
                title="HVCI incompatible: " + ", ".join(reasons),
                severity=Severity.HIGH,
                description="This driver is NOT compatible with Hypervisor-protected Code "
                            "Integrity (HVCI / Memory Integrity). On systems with HVCI "
                            "enabled, Windows will BLOCK this driver from loading. "
                            f"Issues: {', '.join(reasons)}.",
                location="PE Headers / Sections",
                details={"force_integrity": str(force_integrity),
                         "has_wx_sections": str(has_wx)},
            ))
            load_status.append((False, "HVCI",
                                f"Blocked when Memory Integrity is ON ({', '.join(reasons)})"))
        else:
            load_status.append((True, "HVCI", "Compatible with Memory Integrity"))

        # ── 5. Secure Boot enforcement ────────────────────────────────────
        if not is_signed or is_self_signed:
            load_status.append((False, "Secure Boot",
                                "Blocked when Secure Boot is enabled"))
        elif blocked:
            load_status.append((False, "Secure Boot",
                                "Blocked by DriverSiPolicy under Secure Boot"))
        else:
            load_status.append((True, "Secure Boot",
                                "Compatible (signed driver)"))

        # ── 6. Architecture check ─────────────────────────────────────────
        self.findings.append(Finding(
            title=f"Driver architecture: {'x64' if is_64 else 'x86 (32-bit)'}",
            severity=Severity.INFO if is_64 else Severity.MEDIUM,
            description=f"{'64-bit driver — loads on x64 Windows' if is_64 else '32-bit driver — will NOT load on 64-bit Windows. Modern Windows x64 does not support 32-bit kernel drivers.'}",
            location="PE Header",
        ))
        if not is_64:
            load_status.append((False, "Architecture",
                                "32-bit driver cannot load on 64-bit Windows"))

        # ── 6b. Timestamp quality for load ────────────────────────────────
        ts_signer = ci.get("timestamp_signer", "")
        if is_signed and is_expired and not ts_signer:
            load_status.append((False, "Timestamp",
                                "Expired cert + no timestamp = signature rejected"))
        elif is_signed and is_expired and ts_signer:
            load_status.append((True, "Timestamp",
                                f"Expired cert but timestamped by {ts_signer}"))
        elif is_signed and ts_signer:
            load_status.append((True, "Timestamp",
                                f"Valid timestamp by {ts_signer}"))

        # ── 6c. Test-signed detection ─────────────────────────────────────
        if is_signed and not is_self_signed:
            signer_lower = (ci.get("signer_cn", "") + " " + ci.get("signer_org", "")).lower()
            test_indicators = ["test", "debug", "dev cert", "development"]
            is_test_signed = any(ind in signer_lower for ind in test_indicators)
            if is_test_signed:
                load_status.append((False, "Test Certificate",
                                    "Test-signed — requires TESTSIGNING mode"))
                self.findings.append(Finding(
                    title="Driver appears to be test-signed",
                    severity=Severity.HIGH,
                    description=f"Signer '{ci.get('signer_cn', '')}' suggests test-signing. "
                                "Requires bcdedit /set testsigning on (disables Secure Boot).",
                    location="Signature Policy",
                ))

        # ── 6d. Subsystem check ───────────────────────────────────────────
        if not self.pe.is_driver:
            load_status.append((False, "Subsystem",
                                "PE Subsystem != NATIVE (1) — not recognized as kernel driver"))
            self.findings.append(Finding(
                title="PE Subsystem is not NATIVE — may not load as kernel driver",
                severity=Severity.HIGH,
                description="PE Subsystem is not IMAGE_SUBSYSTEM_NATIVE (1). "
                            "Windows kernel driver loader requires Subsystem=NATIVE.",
                location="PE Header",
            ))

        # ── 6e. Revoked cert blocks loading ───────────────────────────────
        signer_serial = ci.get("signer_serial", "")
        serial_lower = signer_serial.lower().lstrip("0") if signer_serial else ""
        for rev_serial in KNOWN_REVOKED_CERTS:
            if serial_lower and serial_lower == rev_serial.lower().lstrip("0"):
                load_status.append((False, "Revoked Certificate",
                                    "Signing cert is revoked — Windows will reject"))
                break

        # ── 7. Per-configuration load matrix ──────────────────────────────
        matrix = self._build_load_matrix(ci, sf, is_64, sha, blocked)

        # Legacy flat summary (still used by some consumers)
        can_load_all = all(s[0] for s in load_status)
        blockers = [s for s in load_status if not s[0]]
        passers = [s for s in load_status if s[0]]

        summary_lines = []
        for ok, cond, detail in load_status:
            mark = "[PASS]" if ok else "[BLOCKED]"
            summary_lines.append(f"  {mark} {cond}: {detail}")

        if can_load_all:
            overall = "LOADABLE — This driver should load on modern Windows"
            sev = Severity.INFO
        elif blockers:
            overall = f"BLOCKED — {len(blockers)} issue(s) prevent loading"
            sev = Severity.HIGH
        else:
            overall = "UNKNOWN — Could not fully determine load status"
            sev = Severity.MEDIUM

        self.findings.append(Finding(
            title=f"Load compatibility: {overall}",
            severity=sev,
            description="\n".join(summary_lines),
            location="Load Policy Analysis",
            details={
                "can_load": str(can_load_all),
                "blockers": [s[1] for s in blockers],
                "passes": [s[1] for s in passers],
                "matrix": matrix,
            },
        ))

    def _build_load_matrix(self, ci, sf, is_64, sha, ms_blocklist_hit):
        """Compute verdicts per Windows boot/policy configuration.

        Returns a dict keyed by config name → {
            verdict: "WILL_LOAD" | "WILL_NOT_LOAD" | "CONDITIONAL" | "UNKNOWN",
            blockers: [str],
            passes: [str],
        }.
        Configs: default, secure_boot, hvci, test_signing, s_mode.
        """
        is_signed       = ci.get("signed", False)
        is_self_signed  = ci.get("signer_self_signed", False)
        is_expired      = ci.get("signer_expired", False)
        sig_valid       = ci.get("signature_valid")
        pe_hash_match   = ci.get("pe_hash_match")
        anchor          = ci.get("chain_anchor") or {}
        kernel_anchor   = anchor.get("trusted_for_kernel", False)
        anchor_kind     = anchor.get("kind", "unknown")
        ts_valid        = ci.get("timestamp_valid")
        ts_source       = ci.get("countersig_source", "")
        # A decoded countersignature time is what Windows actually consults.
        # Our own crypto-verify failing (ts_valid=False) does NOT translate
        # to "Windows will reject" — legacy TSA encodings routinely fail our
        # re-verify but pass real CryptoAPI. Treat TS as *present* whenever
        # a time was successfully decoded.
        ts_time         = ci.get("countersig_time") or ""
        ts_present      = bool(ts_time)
        signing_time    = ts_time or ci.get("signing_time") or ""
        has_whql        = ci.get("has_whql_eku", False)
        has_ev          = ci.get("has_ev_cert", False)
        page_hashes     = ci.get("page_hashes_present", False)
        force_integrity = sf.get("FORCE_INTEGRITY", False)
        has_wx          = any(s["writable"] and s["executable"] for s in self.pe.sections)
        nested          = ci.get("nested_signatures") or []
        any_nested_ok   = any(n.get("signature_valid") is True and
                              n.get("pe_hash_match") is not False for n in nested)
        effectively_verified = (
            (sig_valid is True and pe_hash_match is not False) or any_nested_ok)

        # Grandfathering gates — Windows continues to load pre-cutoff drivers
        # as long as they were timestamped before the respective deadline.
        #   SHA-1 kernel cutoff       : 2015-07-29
        #   Cross-sign new-sign cutoff: 2021-07-01
        signed_before_sha1_cutoff = bool(
            ts_time and ts_time[:10] < "2015-07-29")
        signed_before_crosssign_cutoff = bool(
            ts_time and ts_time[:10] < "2021-07-01")

        # ── Universal blockers (fail in EVERY configuration) ──────────
        universal: list = []
        if not is_64:
            universal.append("32-bit driver cannot load on 64-bit Windows")
        if not self.pe.is_driver:
            universal.append("PE Subsystem is not NATIVE")
        if is_signed and sig_valid is False and not any_nested_ok:
            universal.append(f"PKCS#7 signature fails crypto verification "
                             f"({ci.get('signature_error', 'unknown')})")
        if is_signed and pe_hash_match is False and not any_nested_ok:
            universal.append("Authenticode PE hash mismatch — binary tampered "
                             "post-signing")
        # Revoked signer serial
        signer_serial = ci.get("signer_serial", "")
        serial_lower = signer_serial.lower().lstrip("0") if signer_serial else ""
        from drivertool.constants import KNOWN_REVOKED_CERTS
        for rev_serial, rev_desc in KNOWN_REVOKED_CERTS.items():
            if serial_lower and serial_lower == rev_serial.lower().lstrip("0"):
                universal.append(f"Signer certificate REVOKED: {rev_desc}")
                break

        # EKU propagation — intermediates that carry EKU must include
        # codeSigning; otherwise Windows rejects the chain.
        if ci.get("eku_propagation_ok") is False:
            universal.append(
                f"EKU propagation broken: intermediate CA "
                f"'{ci.get('eku_broken_cert_cn', '?')}' carries an EKU list "
                "that excludes codeSigning")

        # Live Microsoft disallowedcert.stl — thumbprint match on any cert
        # in the chain means Windows will refuse the binary outright.
        if LIVE_DISALLOWED_THUMBPRINTS or LIVE_DISALLOWED_THUMBPRINTS_SHA256:
            for c in ci.get("certificates", []):
                tp1 = (c.get("thumbprint_sha1") or "").lower()
                tp2 = (c.get("thumbprint_sha256") or "").lower()
                if ((tp1 and tp1 in LIVE_DISALLOWED_THUMBPRINTS) or
                        (tp2 and tp2 in LIVE_DISALLOWED_THUMBPRINTS_SHA256)):
                    universal.append(
                        f"Chain cert '{c.get('subject_cn', '?')}' is on "
                        f"Microsoft's live disallowedcert.stl")
                    break

        # Cross-signing deadline — MS stopped honoring NEW cross-sign
        # submissions after 2021-07-01. Drivers timestamped before that
        # still load indefinitely. If the TS is absent we can't prove
        # pre-deadline status — be conservative and treat as post-deadline.
        cross_sign_past_deadline = (
            anchor_kind == "cross-sign" and not signed_before_crosssign_cutoff)

        # SHA-1 primary digest — rejected on modern Windows ONLY if the
        # driver was signed after the 2015-07-29 kernel SHA-1 cutoff AND
        # no SHA-256 nested signature exists.
        primary_digest_oid = ""
        try:
            # The authoritative value is the Authenticode PE-hash OID, which
            # we store as the short name in `pe_hash_algorithm`.
            primary_digest_oid = (ci.get("pe_hash_algorithm") or "").lower()
        except Exception:
            pass
        primary_is_sha1 = "sha1" in primary_digest_oid
        nested_modern_ok = any(
            (n.get("digest_algorithm") or "").lower() in ("sha256", "sha384", "sha512")
            and n.get("signature_valid") is True
            and n.get("pe_hash_match") is not False
            for n in nested)
        # Grandfathered: SHA-1 + timestamped before 2015-07-29 → still loads.
        sha1_blocked_today = (
            primary_is_sha1
            and not nested_modern_ok
            and not signed_before_sha1_cutoff)

        likely_cat = ci.get("likely_catalog_signed", False)
        cat_reason = ci.get("catalog_sign_reason", "")

        CAT_UNSIGNED_BLOCKERS = {
            "Driver is not signed",
            "Unsigned",
            "Unsigned — test-signing still needs any signature",
        }

        # ── Helper to build a config result ──────────────────────────
        def mk(config_blockers, passes):
            verdict = "WILL_LOAD" if not config_blockers else "WILL_NOT_LOAD"
            if not is_signed and not config_blockers:
                verdict = "CONDITIONAL"
            # Unsigned but MS-shipped → likely catalog-signed. If the only
            # reason for WILL_NOT_LOAD is the unsigned-state blocker,
            # upgrade to CONDITIONAL (loads when the catalog is present).
            if (not is_signed and likely_cat and config_blockers and
                    all(b in CAT_UNSIGNED_BLOCKERS for b in config_blockers)):
                verdict = "CONDITIONAL"
            return {
                "verdict": verdict,
                "blockers": list(config_blockers),
                "passes": list(passes),
            }

        matrix = {}

        # ── default (Win10+, no Secure Boot, no HVCI, no test-signing) ──
        # On modern Windows default config, signing is enforced by the
        # kernel PnP loader: must be signed and trusted.
        d_block = list(universal)
        d_pass = []
        if not is_signed:
            d_block.append("Driver is not signed")
            if likely_cat:
                d_pass.append(
                    f"{cat_reason} — loads if matching catalog is registered "
                    "on target system")
        else:
            d_pass.append("Signed")
            if is_self_signed:
                d_block.append("Self-signed — not accepted without test-signing")
            elif is_expired and not ts_present:
                d_block.append("Signer cert expired and no countersignature "
                               "timestamp to prove pre-expiry signing")
            elif not kernel_anchor:
                d_block.append(f"Chain does not anchor to a kernel-trusted root "
                               f"({anchor_kind})")
            else:
                d_pass.append(f"Chain anchored ({anchor_kind})")
                if is_expired and ts_present:
                    d_pass.append(
                        f"Signed {ts_time[:10]} (pre-expiry) — cert expiry "
                        "ignored by Windows")
            if sha1_blocked_today:
                d_block.append("Primary signature is SHA-1, timestamped "
                               "after 2015-07-29 cutoff, and no modern "
                               "nested signature — rejected on Win10 1903+")
            elif primary_is_sha1 and signed_before_sha1_cutoff:
                d_pass.append(
                    "SHA-1 grandfathered (timestamped before "
                    "2015-07-29 kernel cutoff)")
            if effectively_verified:
                d_pass.append("Signature crypto + PE hash OK")
            if ts_present and ts_valid is False and ci.get("timestamp_binding_ok"):
                d_pass.append(
                    f"Counter-sig binds to primary ({ts_time[:10]}); legacy "
                    "TSA crypto — Windows CryptoAPI accepts it")
        matrix["default"] = mk(d_block, d_pass)

        # ── Secure Boot + DSE ─────────────────────────────────────────
        sb_block = list(matrix["default"]["blockers"])
        sb_pass = list(matrix["default"]["passes"])
        if ms_blocklist_hit:
            sb_block.append("On Microsoft vulnerable-driver block list")
        if cross_sign_past_deadline:
            sb_block.append("Cross-signed after 2021-07-01 cut-off")
        matrix["secure_boot"] = mk(sb_block, sb_pass)

        # ── HVCI / Memory Integrity ───────────────────────────────────
        # HVCI on a default Win10/11 box only rejects on: W+X sections,
        # missing FORCE_INTEGRITY, block-list hits, or broken signatures.
        # Page-hashes and WHQL/EV are S-Mode / Secured-Core requirements,
        # NOT baseline HVCI — most pre-existing signed drivers load fine.
        hvci_block = list(matrix["secure_boot"]["blockers"])
        hvci_pass = list(matrix["secure_boot"]["passes"])
        if not force_integrity:
            hvci_block.append("FORCE_INTEGRITY flag not set (HVCI requires it "
                              "on the PE header)")
        if has_wx:
            hvci_block.append("W+X section present (HVCI forbids RWX)")
        if has_whql:
            hvci_pass.append("WHQL attestation EKU present (Secured-Core ready)")
        if has_ev:
            hvci_pass.append("EV code-signing cert present")
        if page_hashes:
            hvci_pass.append(f"Page hashes present ({ci.get('page_hashes_algorithm', '?')})")
        matrix["hvci"] = mk(hvci_block, hvci_pass)

        # ── test-signing mode (bcdedit /set testsigning on) ───────────
        ts_block = []
        if not is_64:
            ts_block.append("32-bit driver cannot load on 64-bit Windows")
        if not self.pe.is_driver:
            ts_block.append("PE Subsystem is not NATIVE")
        # Test-signing only requires *a* signature and intact binary
        if is_signed and pe_hash_match is False and not any_nested_ok:
            ts_block.append("Authenticode PE hash mismatch (tampered)")
        if not is_signed:
            ts_block.append("Unsigned — test-signing still needs any signature")
        # Test-signing skips chain trust; still rejects forged signatures
        if is_signed and sig_valid is False and not any_nested_ok:
            ts_block.append("PKCS#7 crypto fails")
        ts_pass = []
        if is_signed and effectively_verified:
            ts_pass.append("Any valid signature accepted under test-signing")
        matrix["test_signing"] = mk(ts_block, ts_pass)

        # ── S mode / Secured-Core PC (WHQL + page-hashes required) ────
        s_block = list(universal)
        s_pass = []
        if not is_signed:
            s_block.append("Unsigned")
        if not has_whql:
            s_block.append("No WHQL attestation EKU — S Mode / Secured-Core "
                           "require WHQL-signed drivers")
        else:
            s_pass.append("WHQL attestation EKU present")
        if not page_hashes:
            s_block.append("No Authenticode page hashes "
                           "(Secured-Core requires per-page integrity)")
        else:
            s_pass.append(f"Page hashes present ({ci.get('page_hashes_algorithm', '?')})")
        if ms_blocklist_hit:
            s_block.append("On Microsoft vulnerable-driver block list")
        if not kernel_anchor:
            s_block.append("Chain not kernel-trusted")
        matrix["s_mode"] = mk(s_block, s_pass)

        return matrix
