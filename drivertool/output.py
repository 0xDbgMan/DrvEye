"""Narrative output — prints findings with colored severity tags."""
from __future__ import annotations

from collections import Counter
from typing import List

import logging

from drivertool.constants import Severity
from drivertool.models import Finding

logger = logging.getLogger(__name__)


class NarrativeOutput:
    """Live narrative output — prints findings as they happen."""
    COLORS = {
        Severity.CRITICAL: "\033[91m",
        Severity.HIGH:     "\033[31m",
        Severity.MEDIUM:   "\033[33m",
        Severity.LOW:      "\033[36m",
        Severity.INFO:     "\033[37m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"

    def __init__(self, no_color: bool = False):
        if no_color:
            self.COLORS = {s: "" for s in Severity}
            self.RESET = self.BOLD = self.DIM = ""
        else:
            self._enable_windows_ansi()

    def _enable_windows_ansi(self):
        try:
            import ctypes as ct
            k32 = ct.windll.kernel32
            k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
        except Exception:
            logger.debug("Failed to enable Windows ANSI mode", exc_info=True)

    def info(self, msg: str):
        print(f"[*] {msg}")

    def good(self, msg: str):
        print(f"{self.BOLD}[+]{self.RESET} {msg}")

    def finding(self, f: Finding):
        if f.severity == Severity.INFO:
            return
        color = self.COLORS.get(f.severity, "")
        tag = "!" if f.severity >= Severity.HIGH else "*"
        print(f"{color}[{tag}] {f.severity.name}: {f.title}{self.RESET}")
        if f.description:
            print(f"    {self.DIM}{f.description}{self.RESET}")

    def warn(self, msg: str):
        print(f"\033[33m[!]{self.RESET} {msg}" if self.RESET else f"[!] {msg}")

    def summary(self, findings: List[Finding]):
        counts = Counter(f.severity for f in findings if f.severity > Severity.INFO)
        total = sum(counts.values())
        parts = []
        for sev in reversed(list(Severity)):
            c = counts.get(sev, 0)
            if c > 0:
                color = self.COLORS.get(sev, "")
                parts.append(f"{color}{c} {sev.name}{self.RESET}")
        detail = ", ".join(parts) if parts else "none"
        print(f"\n{self.BOLD}[*] Done. {total} vulnerabilities found ({detail}){self.RESET}")
