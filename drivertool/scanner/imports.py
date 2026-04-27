"""Import and compiler security scanning."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from drivertool.constants import DANGEROUS_IMPORTS, Severity
from drivertool.models import Finding

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ImportScanMixin:
    """Mixin: scan_imports, scan_compiler_security"""

    def scan_imports(self):
        all_imports = []
        for dll, funcs in self.pe.imports.items():
            for func in funcs:
                all_imports.append(func)
                if func in DANGEROUS_IMPORTS:
                    sev, desc, hint = DANGEROUS_IMPORTS[func]
                    if sev <= Severity.INFO:
                        continue
                    self.findings.append(Finding(
                        title=f"Dangerous import: {func}",
                        severity=sev,
                        description=desc,
                        location=f"Import Table ({dll})",
                        poc_hint=hint if hint else None,
                        details={"dll": dll, "function": func},
                    ))

        # Check for positive indicators
        has_probe_read = "ProbeForRead" in all_imports
        has_probe_write = "ProbeForWrite" in all_imports
        if not has_probe_read and not has_probe_write:
            dangerous_count = sum(1 for f in all_imports if f in DANGEROUS_IMPORTS
                                  and DANGEROUS_IMPORTS[f][0] >= Severity.HIGH)
            if dangerous_count > 0:
                self.findings.append(Finding(
                    title="No ProbeForRead/ProbeForWrite imports found",
                    severity=Severity.HIGH,
                    description="Driver imports dangerous APIs but never imports "
                                "ProbeForRead or ProbeForWrite. User buffer validation "
                                "is likely missing.",
                    location="Import Table",
                ))

    def scan_compiler_security(self):
        """BinSkim-style check for missing binary security mitigations."""
        feats = getattr(self.pe, "security_flags", None) or self.pe._parse_security_features()
        CHECKS = [
            ("NX_COMPAT",       "DEP/NX (/NXCOMPAT)",
             "Executable pages usable for shellcode without ROP chains."),
            ("DYNAMIC_BASE",    "ASLR (/DYNAMICBASE)",
             "Driver loads at predictable address — KASLR bypass trivial."),
            ("FORCE_INTEGRITY", "Signature enforcement (FORCE_INTEGRITY)",
             "Driver can load without a valid Authenticode signature."),
            ("GUARD_CF",        "Control Flow Guard (/guard:cf)",
             "Indirect calls unvalidated — control-flow hijacking easier."),
            ("GS_COOKIE",       "Stack canary (/GS)",
             "Stack overflows not detected by compiler canary check."),
            ("HIGH_ENTROPY_VA", "High-entropy ASLR (/HIGHENTROPYVA)",
             "64-bit ASLR entropy reduced — address brute-force more feasible."),
        ]
        for key, name, risk in CHECKS:
            if not feats.get(key, False):
                self.findings.append(Finding(
                    title=f"Missing mitigation: {name}",
                    severity=Severity.MEDIUM,
                    description=f"{name} is not enabled. {risk}",
                    location="PE DllCharacteristics / LoadConfig",
                    details={"mitigation": name, "flag": key},
                ))
        if feats.get("HVCI_COMPATIBLE"):
            self.findings.append(Finding(
                title="Driver is HVCI-compatible",
                severity=Severity.INFO,
                description="FORCE_INTEGRITY set and no W+X sections. "
                            "Meets basic HVCI (Hypervisor-Protected Code Integrity) requirements.",
                location="PE headers",
                details={"hvci": "compatible"},
            ))
        else:
            self.findings.append(Finding(
                title="Driver is NOT HVCI-compatible",
                severity=Severity.HIGH,
                description="Driver fails HVCI checks (missing FORCE_INTEGRITY or has W+X sections). "
                            "Cannot load in HVCI-enabled environments without policy bypass.",
                location="PE headers",
                details={"hvci": "incompatible"},
            ))
