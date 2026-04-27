"""YARA rule generation from analysis results."""
from __future__ import annotations

import os
import re
import struct
from typing import TYPE_CHECKING, List

from drivertool.ioctl import HANDLER_PURPOSE_MAP

if TYPE_CHECKING:
    from drivertool.pe_analyzer import PEAnalyzer
    from drivertool.scanner import VulnScanner


def generate_yara_rule(pe_info: dict, scanner: "VulnScanner",
                       pe_analyzer: "PEAnalyzer") -> str:
    """
    Auto-generate a YARA rule for the analyzed driver based on:
    - Device name strings
    - Critical IAT entries (HANDLER_PURPOSE_MAP functions)
    - Specific IOCTL constants found
    Returns the YARA rule as a string.
    """
    sha = pe_info.get("sha256", "unknown")[:16]
    fname = os.path.basename(pe_info.get("filepath", "driver")).replace(".", "_")
    vi = pe_info.get("version_info", {})
    orig = vi.get("OriginalFilename", fname)

    rule_name = re.sub(r"[^A-Za-z0-9_]", "_", fname)

    strings: List[str] = []
    conditions: List[str] = ["uint16(0) == 0x5A4D"]
    sid = 0

    # Device name strings (wide)
    for dn in pe_analyzer.device_names[:3]:
        sid += 1
        escaped = dn.replace("\\", "\\\\")
        strings.append(f'        $dev{sid} = "{escaped}" wide')
        conditions.append(f"$dev{sid}")

    # Critical imports
    critical_imports: List[str] = []
    for dll_funcs in pe_analyzer.imports.values():
        for func in dll_funcs:
            if func in HANDLER_PURPOSE_MAP:
                critical_imports.append(func)
    for imp in critical_imports[:5]:
        sid += 1
        strings.append(f'        $imp{sid} = "{imp}"')

    if critical_imports:
        imp_names = " or ".join(f"$imp{i}" for i in range(sid - len(critical_imports[:5]) + 1, sid + 1))
        conditions.append(f"({imp_names})")

    # IOCTL constants as hex bytes
    for code in scanner.ioctl_codes[:4]:
        sid += 1
        b = struct.pack("<I", code)
        hex_str = " ".join(f"{byte:02X}" for byte in b)
        strings.append(f"        $ioctl{sid} = {{ {hex_str} }}")

    if scanner.ioctl_codes:
        ioctl_names = " or ".join(f"$ioctl{i}" for i in range(sid - len(scanner.ioctl_codes[:4]) + 1, sid + 1))
        conditions.append(f"({ioctl_names})")

    # Purpose annotation
    purposes = list(set(scanner.ioctl_purposes.values()))
    purpose_meta = ", ".join(sorted(set(purposes))) if purposes else "unknown"

    rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated rule for {orig}"
        sha256_prefix = "{sha}"
        capabilities = "{purpose_meta}"
        generated_by = "TheDebugger"
    strings:
{chr(10).join(strings)}
    condition:
        {" and ".join(conditions)}
}}"""
    return rule
