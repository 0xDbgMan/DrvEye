"""JSON export of analysis results."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from drivertool.ioctl import decode_ioctl

if TYPE_CHECKING:
    from drivertool.scanner import VulnScanner


def export_json(pe_info: dict, scanner: "VulnScanner", outpath: str,
                device_names: list = None,
                exploit_chains: list = None) -> None:
    """Serialize full analysis to JSON."""
    # Surface the load verdict so consumers can answer "will it load?"
    # without re-walking findings.
    load_finding = next((f for f in scanner.findings
                         if "Load compatibility" in (f.title or "")), None)
    load_verdict = {}
    if load_finding:
        det = load_finding.details or {}
        load_verdict = {
            "can_load": det.get("can_load", "Unknown"),
            "blockers": det.get("blockers", []),
            "passes":   det.get("passes", []),
        }

    data = {
        "file":     pe_info.get("filepath", ""),
        "sha256":   pe_info.get("sha256", ""),
        "imphash":  pe_info.get("imphash", ""),
        "arch":     pe_info.get("arch", ""),
        "version":  pe_info.get("version_info", {}),
        "security": {k: v for k, v in pe_info.get("security_features", {}).items()},
        "certificate": pe_info.get("certificate", {}),
        "device_names": list(device_names or []),
        "load_verdict": load_verdict,
        "exploit_chains": list(exploit_chains or []),
        "attack_surface_score": scanner.attack_score,
        "attack_risk": scanner.attack_risk,
        "device_access": {
            "create_api": scanner.device_access.get("create_api", ""),
            "secure_open": scanner.device_access.get("secure_open", False),
            "exclusive": scanner.device_access.get("exclusive", False),
            "sddl": scanner.device_access.get("sddl"),
            "symlinks": scanner.device_access.get("symlinks", []),
            "issues": scanner.device_access.get("issues", []),
        } if scanner.device_access else {},
        "ioctls": [
            {
                "code":    f"0x{c:08X}",
                "method":  decode_ioctl(c)["method_name"],
                "access":  decode_ioctl(c)["access_name"],
                "purpose": scanner.ioctl_purposes.get(c, ""),
                "primitives": scanner.ioctl_primitives.get(c, []),
                "bug_classes": scanner.ioctl_bug_classes.get(c, []),
                "struct_fields": scanner.ioctl_structs.get(c, []),
                "behavior": {
                    "api_calls": [ac["name"] for ac in scanner.ioctl_behaviors.get(c, {}).get("api_calls", [])],
                    "categories": list(set(ac["category"] for ac in scanner.ioctl_behaviors.get(c, {}).get("api_calls", []))),
                    "security_checks": scanner.ioctl_behaviors.get(c, {}).get("security_checks", []),
                    "risk_factors": scanner.ioctl_behaviors.get(c, {}).get("risk_factors", []),
                    "inline_ops": [op["type"] for op in scanner.ioctl_behaviors.get(c, {}).get("inline_ops", [])],
                } if c in scanner.ioctl_behaviors else {},
            }
            for c in scanner.ioctl_codes
        ],
        "findings": [
            {
                "title":       f.title,
                "severity":    f.severity.name,
                "description": f.description,
                "location":    f.location,
                "details":     f.details or {},
                "ioctl_code":  f"0x{f.ioctl_code:08X}" if f.ioctl_code else None,
            }
            for f in scanner.findings
        ],
    }
    with open(outpath, "w") as jf:
        json.dump(data, jf, indent=2)
