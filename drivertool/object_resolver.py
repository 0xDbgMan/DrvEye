"""
Object Resolver
===============
Maps kernel objects (devices, symlinks, ALPC ports, sections, events)
recovered from string-constant scanning to actionable attack surface.

Key insights:
*   A driver that creates a DeviceObject but *no* symbolic link is
    unreachable from user-mode via CreateFile/CreateFileW — the attack
    surface is limited (or the link is created dynamically / by a helper
    driver).
*   A symlink whose basename is predictable AND is created without
    OBJ_EXCLUSIVE / permanent-object semantics is vulnerable to a
    **symlink-hijack** (another process can create the same symlink
    first and intercept traffic).
*   ALPC ports, sections, and events expose additional IPC attack surface.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional

from drivertool.pe_analyzer import PEAnalyzer


@dataclass(frozen=True)
class DeviceSymlinkPair:
    """Correlated device-object name ↔ symbolic-link name."""
    device: str          # e.g. \\Device\\MyDriver
    symlink: str         # e.g. \\DosDevices\\MyDriver
    link_type: str = "auto"   # "IoCreateSymbolicLink", "IoCreateUnprotectedSymbolicLink", "auto"


@dataclass
class ObjectResolver:
    """
    Takes a :class:`PEAnalyzer` and resolves relationships between the
    various kernel object strings it has recovered.
    """

    pe_analyzer: PEAnalyzer

    # Results (populated after ``resolve()``)
    pairs: List[DeviceSymlinkPair] = field(default_factory=list)
    unlinked_devices: List[str] = field(default_factory=list)
    hijack_risks: List[str] = field(default_factory=list)
    alpc_ports: List[str] = field(default_factory=list)
    sections: List[str] = field(default_factory=list)
    events: List[str] = field(default_factory=list)

    # Internal bookkeeping
    _device_set: Set[str] = field(default_factory=set, repr=False)
    _symlink_set: Set[str] = field(default_factory=set, repr=False)

    # Known prefixes that indicate the object type from string constants
    _DEVICE_PREFIXES = (
        r"\\Device\\",
        r"\\GLOBAL\\Device\\",
    )
    _SYMLINK_PREFIXES = (
        r"\\DosDevices\\",
        r"\\\?\?\\",
        r"\\GLOBAL\?\?\\",
    )
    _SECTION_PREFIXES = (
        r"\\BaseNamedObjects\\",
        r"\\KernelObjects\\",
        r"\\Sessions\\",
    )
    _ALPC_PREFIXES = (
        r"\\RPC Control\\",
    )
    _EVENT_PREFIXES = (
        r"\\BaseNamedObjects\\",
        r"\\KernelObjects\\",
    )

    # Regex to strip kernel prefixes so we can fuzzy-match basename
    _BASENAME_RE = re.compile(r"^\\(?:Device|DosDevices|\?\?|GLOBAL\?\?|GLOBAL\\Device)\\(.+)$")

    # Symlink basenames that are trivially predictable and therefore
    # high-risk for hijacking if not created exclusively.
    _PREDICTABLE_PATTERNS = (
        re.compile(r"(?i)^driver[a-z0-9]{0,8}$"),
        re.compile(r"(?i)^drv[a-z0-9]{0,8}$"),
        re.compile(r"(?i)^[a-z]{1,4}[0-9]{1,4}$"),
        re.compile(r"(?i)^kbd[a-z0-9]{0,6}$"),
        re.compile(r"(?i)^mouse[a-z0-9]{0,6}$"),
        re.compile(r"(?i)^usb[a-z0-9]{0,6}$"),
        re.compile(r"(?i)^pci[a-z0-9]{0,6}$"),
        re.compile(r"(?i)^ide[a-z0-9]{0,6}$"),
        re.compile(r"(?i)^sata[a-z0-9]{0,6}$"),
        re.compile(r"(?i)^net[a-z0-9]{0,6}$"),
        re.compile(r"(?i)^vmci[a-z0-9]{0,6}$"),
    )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def resolve(self) -> "ObjectResolver":
        """Run all resolution heuristics and return *self*."""
        self._classify_strings()
        self._match_pairs()
        self._find_unlinked()
        self._flag_hijack_risks()
        return self

    def get_accessible_devices(self) -> List[DeviceSymlinkPair]:
        """Return device↔symlink pairs that are reachable from user-mode."""
        return self.pairs

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _classify_strings(self) -> None:
        """Partition raw string constants into object-type buckets."""
        raw: Set[str] = set(getattr(self.pe_analyzer, "device_names", []))
        raw.update(getattr(self.pe_analyzer, "inferred_names", []))
        # Also scan imports / exports for extra hints? Not needed for strings.

        for s in raw:
            s = s.strip()
            if not s:
                continue

            if self._is_device(s):
                self._device_set.add(s)
            elif self._is_symlink(s):
                self._symlink_set.add(s)
            elif self._is_section(s):
                self.sections.append(s)
            elif self._is_alpc(s):
                self.alpc_ports.append(s)
            elif self._is_event(s):
                self.events.append(s)

    def _match_pairs(self) -> None:
        """Fuzzy-match device names to symlink names by basename."""
        # Build basename → symlink mapping
        basename_to_symlink: Dict[str, str] = {}
        for sl in self._symlink_set:
            bn = self._basename(sl)
            if bn:
                basename_to_symlink[bn.lower()] = sl

        for dev in self._device_set:
            bn = self._basename(dev)
            if bn and bn.lower() in basename_to_symlink:
                self.pairs.append(DeviceSymlinkPair(
                    device=dev,
                    symlink=basename_to_symlink[bn.lower()],
                    link_type="auto",
                ))

    def _find_unlinked(self) -> None:
        """Devices with no matching symlink are unlinked."""
        linked_devices = {p.device for p in self.pairs}
        self.unlinked_devices = sorted(
            d for d in self._device_set if d not in linked_devices
        )

    def _flag_hijack_risks(self) -> None:
        """Symlinks whose basename is predictable → hijack risk."""
        linked_symlinks = {p.symlink for p in self.pairs}
        for sl in linked_symlinks:
            short = self._short_name(sl)
            if short and self._is_predictable(short):
                # If the PE also contains IoCreateSymbolicLink (not the
                # "Unprotected" variant) we conservatively flag anyway
                # because OBJ_EXCLUSIVE is rarely set in 3rd-party drivers.
                self.hijack_risks.append(sl)

    # ------------------------------------------------------------------ #
    # Static / class helpers
    # ------------------------------------------------------------------ #

    @classmethod
    def _basename(cls, s: str) -> Optional[str]:
        m = cls._BASENAME_RE.match(s)
        return m.group(1) if m else None

    @classmethod
    def _short_name(cls, s: str) -> Optional[str]:
        """Return the trailing component after the last backslash."""
        if not s:
            return None
        # Handle both forward and back slashes for robustness
        return s.replace("/", "\\").rsplit("\\", 1)[-1]

    @classmethod
    def _is_device(cls, s: str) -> bool:
        return any(re.match(p, s) for p in cls._DEVICE_PREFIXES)

    @classmethod
    def _is_symlink(cls, s: str) -> bool:
        return any(re.match(p, s) for p in cls._SYMLINK_PREFIXES)

    @classmethod
    def _is_section(cls, s: str) -> bool:
        return any(re.match(p, s) for p in cls._SECTION_PREFIXES)

    @classmethod
    def _is_alpc(cls, s: str) -> bool:
        return any(re.match(p, s) for p in cls._ALPC_PREFIXES)

    @classmethod
    def _is_event(cls, s: str) -> bool:
        # Simple heuristic: look like an event name (often has "Event" in it)
        if not any(re.match(p, s) for p in cls._EVENT_PREFIXES):
            return False
        lower = s.lower()
        return "event" in lower or "sync" in lower or "ready" in lower

    @classmethod
    def _is_predictable(cls, short: str) -> bool:
        """Return *True* if the short name looks trivially guessable."""
        for pat in cls._PREDICTABLE_PATTERNS:
            if pat.match(short):
                return True
        return False
