"""Finding dataclass for vulnerability reports."""

from dataclasses import dataclass, field
from typing import Dict, Optional

from drivertool.constants import Severity


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    location: str
    details: Dict[str, str] = field(default_factory=dict)
    poc_hint: Optional[str] = None
    ioctl_code: Optional[int] = None
