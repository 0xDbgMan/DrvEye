"""Source code scanner for C/C++ driver source files."""
from __future__ import annotations

import os
import re
from typing import List

from drivertool.constants import Severity
from drivertool.models import Finding


class SourceScanner:
    PATTERNS = [
        (r'IoCreateDevice\s*\([^)]*,\s*NULL\s*,', Severity.HIGH,
         "IoCreateDevice with NULL security descriptor",
         "Device created without security descriptor — any user can access it."),
        (r'(memcpy|RtlCopyMemory|RtlMoveMemory)\s*\([^)]*(?:Length|Size|Count|Len)',
         Severity.HIGH, "Potential unchecked memcpy with variable size",
         "Memory copy with size parameter — verify size is validated against buffer bounds."),
        (r'#define\s+IOCTL_\w+\s+CTL_CODE\s*\([^)]*METHOD_NEITHER',
         Severity.HIGH, "IOCTL defined with METHOD_NEITHER",
         "IOCTL uses METHOD_NEITHER — raw user pointers passed to kernel."),
        (r'MmMapIoSpace\s*\(', Severity.CRITICAL, "MmMapIoSpace usage in source",
         "Maps physical memory. If address comes from user input, this is arbitrary R/W."),
        (r'__try\s*\{', Severity.INFO, "SEH usage detected",
         "Structured exception handling found — verify __except handler is appropriate."),
        (r'Irp->UserBuffer', Severity.HIGH, "Direct access to Irp->UserBuffer",
         "Direct access to user buffer without ProbeForRead/ProbeForWrite."),
        (r'ExAllocatePool[^(]*\([^)]*\)\s*;(?!\s*if)', Severity.MEDIUM,
         "Pool allocation without NULL check",
         "ExAllocatePool return value may not be checked for NULL."),
        (r'__writemsr|__readmsr', Severity.CRITICAL, "MSR access in source",
         "Direct MSR read/write — can compromise entire system."),
    ]

    def __init__(self, source_paths: List[str]):
        self.source_paths = source_paths
        self.findings: List[Finding] = []

    def scan(self) -> List[Finding]:
        for path in self.source_paths:
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue
            for pattern, severity, title, desc in self.PATTERNS:
                for match in re.finditer(pattern, content):
                    lineno = content[:match.start()].count("\n") + 1
                    self.findings.append(Finding(
                        title=title,
                        severity=severity,
                        description=desc,
                        location=f"{path}:{lineno}",
                        details={"matched_text": match.group()[:120]},
                    ))
        return self.findings
