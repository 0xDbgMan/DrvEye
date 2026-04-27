"""Attack surface scoring."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from drivertool.constants import (
    DANGEROUS_IMPORTS,
    KNOWN_REVOKED_CERTS,
    LOLDRIVERS_HASHES,
    MS_DRIVER_BLOCKLIST,
    Severity,
)
from drivertool.ioctl import decode_ioctl
from drivertool.models import Finding

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ScoringScanMixin:
    """Mixin for attack surface scoring."""

    def compute_attack_surface_score(self) -> int:
        """
        Compute a quantitative attack surface score (0-100) for the driver.
        Higher = more dangerous / more exploitable.

        Factors:
         - IOCTL exposure (count, methods, access rights)
         - Exploit primitives available
         - Missing mitigations
         - Certificate issues
         - Access control gaps
         - Dangerous imports
         - Unchecked returns
        """
        score = 0.0
        max_score = 100.0

        # ── 1. IOCTL Exposure (0-20 pts) ──────────────────────────────────
        n_ioctls = len(self.ioctl_codes)
        score += min(n_ioctls * 2, 10)  # up to 10 pts for IOCTL count

        # METHOD_NEITHER IOCTLs (very dangerous)
        neither_count = sum(1 for c in self.ioctl_codes if (c & 3) == 3)
        score += min(neither_count * 3, 6)

        # FILE_ANY_ACCESS IOCTLs
        any_access = sum(1 for c in self.ioctl_codes if decode_ioctl(c)["access"] == 0)
        score += min(any_access * 1.5, 4)

        # ── 2. Exploit Primitives (0-25 pts) ──────────────────────────────
        all_prims = set()
        for prims in self.ioctl_primitives.values():
            all_prims.update(prims)

        prim_scores = {
            "arbitrary-write": 8, "arbitrary-read": 5, "code-execution": 8,
            "physical-rw": 7, "msr-rw": 7, "token-steal": 6,
            "ppl-bypass": 5, "process-control": 4, "pool-overflow": 5,
            "info-leak": 3, "arbitrary-increment": 4, "denial-of-service": 2,
        }
        prim_pts = sum(prim_scores.get(p, 1) for p in all_prims)
        score += min(prim_pts, 25)

        # ── 3. Missing Mitigations (0-15 pts) ─────────────────────────────
        sf = getattr(self.pe, "security_flags", {})
        if not sf.get("NX_COMPAT"):
            score += 2
        if not sf.get("DYNAMIC_BASE"):
            score += 2
        if not sf.get("GS_COOKIE"):
            score += 3
        if not sf.get("GUARD_CF"):
            score += 2
        if not sf.get("FORCE_INTEGRITY"):
            score += 2
        if not sf.get("HVCI_COMPATIBLE"):
            score += 2
        # W+X sections
        if any(s["writable"] and s["executable"] for s in self.pe.sections):
            score += 2

        # ── 4. Certificate Issues (0-10 pts) ──────────────────────────────
        ci = self.pe.cert_info
        if not ci.get("signed"):
            score += 5
        elif ci.get("signer_self_signed"):
            score += 4
        elif ci.get("signer_expired") and not ci.get("timestamp_signer"):
            score += 3
        elif ci.get("signer_expired"):
            score += 1

        # Weak key
        if ci.get("signer_key_type") == "RSA" and (ci.get("signer_key_size", 4096) < 2048):
            score += 2

        # Known revoked
        serial = ci.get("signer_serial", "").lower().lstrip("0")
        for rev_serial in KNOWN_REVOKED_CERTS:
            if serial and serial == rev_serial.lower().lstrip("0"):
                score += 3
                break

        # ── 5. Access Control Gaps (0-10 pts) ─────────────────────────────
        for f in self.findings:
            t = f.title.lower()
            if "no previousmode" in t:
                score += 3
            elif "missing inputbufferlength" in t:
                score += 2
            elif "missing null buffer" in t:
                score += 1.5
            elif "no privilege check" in t:
                score += 1.5
            elif "iocreatedevice without" in t:
                score += 2
            elif "obreferenceobjectbyhandle with kernelmode" in t:
                score += 3
            elif "missing default case" in t:
                score += 1

        # ── 6. Dangerous Imports (0-10 pts) ────────────────────────────────
        all_imports = set(f for funcs in self.pe.imports.values() for f in funcs)
        crit_imports = sum(1 for f in all_imports
                          if f in DANGEROUS_IMPORTS and
                          DANGEROUS_IMPORTS[f][0] >= Severity.CRITICAL)
        high_imports = sum(1 for f in all_imports
                          if f in DANGEROUS_IMPORTS and
                          DANGEROUS_IMPORTS[f][0] == Severity.HIGH)
        score += min(crit_imports * 2 + high_imports * 0.5, 10)

        # ── 7. Unchecked Returns (0-5 pts) ─────────────────────────────────
        unchecked_count = sum(1 for f in self.findings
                             if "unchecked return" in f.title.lower())
        score += min(unchecked_count * 1.5, 5)

        # ── 8. LOLDrivers / MS Block List (0-5 pts) ───────────────────────
        sha = self.pe.file_hash
        if sha in LOLDRIVERS_HASHES:
            score += 3
        if sha in MS_DRIVER_BLOCKLIST:
            score += 2

        # Clamp to 0-100
        final = int(min(max(score, 0), max_score))

        # Determine risk level
        if final >= 80:
            risk = "CRITICAL"
            risk_sev = Severity.CRITICAL
            risk_desc = "Extremely dangerous — likely exploitable with minimal effort"
        elif final >= 60:
            risk = "HIGH"
            risk_sev = Severity.HIGH
            risk_desc = "High risk — multiple exploit primitives and weak security posture"
        elif final >= 40:
            risk = "MEDIUM"
            risk_sev = Severity.MEDIUM
            risk_desc = "Moderate risk — some attack surface but exploitation may be complex"
        elif final >= 20:
            risk = "LOW"
            risk_sev = Severity.LOW
            risk_desc = "Low risk — limited attack surface with reasonable mitigations"
        else:
            risk = "MINIMAL"
            risk_sev = Severity.INFO
            risk_desc = "Minimal attack surface — well-hardened driver"

        # Build score breakdown
        breakdown = []
        breakdown.append(f"IOCTL Exposure    : {min(n_ioctls*2,10) + min(neither_count*3,6) + min(any_access*1.5,4):.0f}/20")
        breakdown.append(f"Exploit Primitives: {min(prim_pts,25)}/25  ({', '.join(sorted(all_prims)) or 'none'})")
        mit_pts = sum([
            2 if not sf.get("NX_COMPAT") else 0,
            2 if not sf.get("DYNAMIC_BASE") else 0,
            3 if not sf.get("GS_COOKIE") else 0,
            2 if not sf.get("GUARD_CF") else 0,
            2 if not sf.get("FORCE_INTEGRITY") else 0,
            2 if not sf.get("HVCI_COMPATIBLE") else 0,
            2 if any(s["writable"] and s["executable"] for s in self.pe.sections) else 0,
        ])
        breakdown.append(f"Missing Mitigations: {mit_pts}/15")
        breakdown.append(f"Certificate Issues : {int(score) - int(score - 10)}/10")  # approximate
        breakdown.append(f"Dangerous Imports  : {min(crit_imports*2 + high_imports*0.5, 10):.0f}/10")

        self.attack_score = final
        self.attack_risk = risk

        self.findings.append(Finding(
            title=f"Attack Surface Score: {final}/100 [{risk}]",
            severity=risk_sev,
            description=f"{risk_desc}\n\nScore breakdown:\n" + "\n".join(f"  {b}" for b in breakdown),
            location="Overall Assessment",
            details={
                "score": str(final),
                "risk": risk,
                "primitives": sorted(all_prims),
                "ioctl_count": str(n_ioctls),
                "method_neither_count": str(neither_count),
            },
        ))

        return final
