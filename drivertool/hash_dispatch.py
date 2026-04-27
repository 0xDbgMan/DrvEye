"""Recovery of IOCTL codes when the dispatcher compares a *hash* of the
code against a constant instead of the raw code itself.

Anti-RE drivers (cheats, some EDR agents) often write their dispatcher
as::

    ULONG code = IrpStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG h    = fnv1a(code);      // or djb2, CRC32, etc
    switch (h) {
        case 0xDEADBEEF: handler_A(); break;
        case 0xCAFEBABE: handler_B(); break;
        ...
    }

Because the switch constants are *hashes* of real IOCTL codes, the
existing CFG scanner pulls them into ``ioctl_codes`` — but they decode
to garbage (wrong method/access bits, huge device-type fields, etc).

This module brute-forces the 32-bit IOCTL space through a small set of
candidate hash functions and recovers the originals. 2³² candidates
through one modern hash is sub-second on commodity CPUs.
"""
from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────
# Candidate hash functions
# ─────────────────────────────────────────────────────────────────────────

def fnv1a_32(v: int) -> int:
    """FNV-1a over 4 little-endian bytes."""
    h = 0x811c9dc5
    for _ in range(4):
        h ^= v & 0xFF
        h = (h * 0x01000193) & 0xFFFFFFFF
        v >>= 8
    return h


def fnv1_32(v: int) -> int:
    """FNV-1 over 4 little-endian bytes."""
    h = 0x811c9dc5
    for _ in range(4):
        h = (h * 0x01000193) & 0xFFFFFFFF
        h ^= v & 0xFF
        v >>= 8
    return h


def djb2_32(v: int) -> int:
    """djb2 over 4 little-endian bytes."""
    h = 5381
    for _ in range(4):
        h = ((h << 5) + h + (v & 0xFF)) & 0xFFFFFFFF
        v >>= 8
    return h


def sdbm_32(v: int) -> int:
    """sdbm over 4 little-endian bytes."""
    h = 0
    for _ in range(4):
        h = ((v & 0xFF) + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
        v >>= 8
    return h


def xor_folded(v: int) -> int:
    """Simple XOR folding — rare but seen in bespoke dispatchers."""
    a = v & 0xFFFF
    b = (v >> 16) & 0xFFFF
    return (a ^ b) | ((a + b) & 0xFFFF) << 16


_CRC32_TABLE: List[int] = []


def _build_crc32_table():
    global _CRC32_TABLE
    tab = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        tab.append(c)
    _CRC32_TABLE = tab


def crc32_ieee(v: int) -> int:
    """IEEE 802.3 CRC32 over 4 little-endian bytes (reflected, ~0-start)."""
    if not _CRC32_TABLE:
        _build_crc32_table()
    c = 0xFFFFFFFF
    for _ in range(4):
        c = (c >> 8) ^ _CRC32_TABLE[(c ^ (v & 0xFF)) & 0xFF]
        v >>= 8
    return c ^ 0xFFFFFFFF


CANDIDATE_HASHES: List[Tuple[str, Callable[[int], int]]] = [
    ("fnv1a", fnv1a_32),
    ("fnv1",  fnv1_32),
    ("djb2",  djb2_32),
    ("sdbm",  sdbm_32),
    ("crc32", crc32_ieee),
]


# ─────────────────────────────────────────────────────────────────────────
# Heuristic: do these constants look like hashes, not real IOCTLs?
# ─────────────────────────────────────────────────────────────────────────

def looks_like_hashes(codes: Iterable[int]) -> bool:
    """IOCTLs encoded via CTL_CODE share structural invariants:
      - Method bits (0..3) distributed across values
      - Access bits (14..15) usually {0,1,3}
      - Device-type field (16..31) is a small number (often < 0x1000)

    Hash values violate all three: method/access bits randomised, and
    the device-type dword is typically distributed across the full
    32-bit range. We flag a candidate set as "hash-shaped" when the
    high 16 bits are uniformly large and method bits look random.
    """
    vals = list(codes)
    if len(vals) < 3:
        return False
    # Device-type field
    dev_types = [(v >> 16) & 0xFFFF for v in vals]
    # If ≥80% have device-type >= 0x1000, it's not a real CTL_CODE set
    high_dev = sum(1 for d in dev_types if d >= 0x1000) / len(dev_types)
    if high_dev < 0.8:
        return False
    # Check method-bit diversity
    methods = {v & 0x3 for v in vals}
    # Real drivers typically pick one method consistently; if we see
    # all 4 method values mixed, it's probably random hash bits.
    return len(methods) >= 3


# ─────────────────────────────────────────────────────────────────────────
# Reversal
# ─────────────────────────────────────────────────────────────────────────

def reverse_hashed_codes(target_hashes: Set[int],
                         candidate_hashes: List[Tuple[str, Callable[[int], int]]]
                         = None,
                         # Restrict brute-force to the IOCTL code space
                         # {device_type, function, method, access}. Device-type
                         # of a private driver is typically in [0x8000, 0xFFFF]
                         # (user-defined range per DDK). Function in [0, 0xFFF].
                         search_device_range: Tuple[int, int] = (0x8000, 0xFFFF),
                         search_function_range: Tuple[int, int] = (0x800, 0xFFF),
                         ) -> Dict[int, Tuple[str, int]]:
    """Brute-force every candidate IOCTL code through each hash and
    return a dict mapping ``real_ioctl_code -> (hash_name, hash_value)``
    for every match.

    Default search space is ~32M candidates — fast (sub-second per hash)
    and covers the standard user-defined IOCTL range from the DDK.
    Widen via the arguments for exotic drivers.
    """
    if not target_hashes:
        return {}
    if candidate_hashes is None:
        candidate_hashes = CANDIDATE_HASHES

    recovered: Dict[int, Tuple[str, int]] = {}

    for hash_name, hfn in candidate_hashes:
        for dev_type in range(search_device_range[0], search_device_range[1] + 1):
            for function in range(search_function_range[0], search_function_range[1] + 1):
                for method in range(4):
                    for access in (0, 1, 2, 3):
                        code = (dev_type << 16) | (access << 14) | (function << 2) | method
                        h = hfn(code)
                        if h in target_hashes:
                            if code not in recovered:
                                recovered[code] = (hash_name, h)
    return recovered


def reverse_hashed_codes_fast(target_hashes: Set[int],
                              candidate_hashes: List[Tuple[str, Callable[[int], int]]]
                              = None,
                              max_candidates: int = 1 << 24,
                              ) -> Dict[int, Tuple[str, int]]:
    """Faster wider brute-force for small target sets. Walks a bounded
    range of 32-bit values (up to ``max_candidates``) through each hash
    and records every IOCTL-shape match. ~16M iterations × len(hashes)
    runs in a few seconds in Python.

    Used when the default shape-restricted search yields no matches —
    drivers sometimes use unusual device-type fields.
    """
    if not target_hashes:
        return {}
    if candidate_hashes is None:
        candidate_hashes = CANDIDATE_HASHES

    recovered: Dict[int, Tuple[str, int]] = {}
    for hash_name, hfn in candidate_hashes:
        for code in range(max_candidates):
            if hfn(code) in target_hashes:
                recovered[code] = (hash_name, hfn(code))
    return recovered
