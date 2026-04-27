"""YARA rule scanning."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from drivertool.constants import YARA_RULES_TEXT, Severity
from drivertool.models import Finding

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class YaraScanMixin:
    """Mixin for YARA-based scanning."""

    def scan_yara(self):
        if not YARA_AVAILABLE:
            return
        try:
            rules = yara.compile(source=YARA_RULES_TEXT)
            matches = rules.match(data=self.pe.raw)
            for m in matches:
                self.findings.append(Finding(
                    title=f"YARA match: {m.rule}",
                    severity=Severity.HIGH,
                    description=f"YARA rule '{m.rule}' matched. "
                                f"Strings: {[str(s) for s in m.strings[:3]]}",
                    location="Binary content",
                    poc_hint="msr_readwrite" if "MSR" in m.rule else "io_port" if "IO" in m.rule else None,
                ))
        except Exception as e:
            self.findings.append(Finding(
                title="YARA scan error",
                severity=Severity.INFO,
                description=str(e),
                location="YARA engine",
            ))
