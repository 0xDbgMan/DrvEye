"""Semantic map of EPROCESS field offsets across Windows builds.

EPROCESS layout changes with each Windows major version — the same
numeric offset means something different on Win7 vs Win10 21H2 vs
Win11 23H2. Drivers that write into EPROCESS almost always target one
of these well-known fields:

  - Token                  : replace the process's token (TOKEN_STEAL)
  - Protection / SignatureLevel / SectionSignatureLevel : clear PPL
  - ActiveProcessLinks     : unlink from the PsActiveProcessHead list
  - ImageFilePointer       : rename the process
  - Pcb.DirectoryTableBase : swap page tables (PTE hijack)
  - Flags / Flags2         : various process flags (e.g. Debugged)

This module classifies a write at offset `disp` with size `size` into
the most likely primitive. Multiple builds can agree on the same field
at slightly different offsets — we model each field as a *range* that
spans every known build and report the matching semantic tag.

Ranges derived from public symbol dumps (WinDbg `dt nt!_EPROCESS`) for
Win7 SP1 x64, Win8.1 x64, Win10 1507..22H2, Win11 21H2..23H2. Values
were consolidated, not per-build lookups — the goal is classification,
not exact struct reconstruction.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────
# Offset ranges (inclusive) → (field_name, primitive_tag)
#
# When a write's offset falls inside one of these ranges with a matching
# access size, the semantic field is identified. `primitive_tag` is the
# exploit primitive the field enables (e.g. "TOKEN_STEAL").
#
# `allowed_sizes` is the write-size-in-bytes set — byte writes to the
# token pointer are not a token steal; qword writes to Protection are
# not a PPL bypass. Requiring the size gate drops a major FP source.
# ──────────────────────────────────────────────────────────────────────────

EPROCESS_FIELDS = [
    # NOTE: we deliberately skip the common "low-offset" EPROCESS fields
    # (DTB at 0x28, Pcb at 0x0, Flags at 0x300-class) because writes at
    # those offsets are indistinguishable from writes to unrelated kernel
    # structs (IRP, DEVICE_OBJECT, driver-private contexts, etc.). We
    # classify only offsets large enough that a write there is much more
    # likely to be an EPROCESS field than some other struct.
    #
    # All ranges below are in the "high tail" of EPROCESS, where almost
    # nothing else kernel-sized lives.

    # Token (OBJECT_HEADER-encoded pointer, qword)
    # Win10 1507..1809: 0x358-0x360  Win10 1903+: 0x360
    # Win10 20H1..22H2: 0x4b8  Win11 21H2+: 0x4b8-0x560
    # We keep only the modern range (Win10 1507+) — pre-Win10 drivers
    # are rare and we'd rather miss than over-tag.
    {"name":  "Token",
     "range": (0x358, 0x560),
     "sizes": {8},
     "primitive": "TOKEN_STEAL"},

    # ImageFilePointer — rename process (Win10 1703..Win11)
    {"name":  "ImageFilePointer",
     "range": (0x418, 0x5b0),
     "sizes": {8},
     "primitive": "PROCESS_RENAME"},

    # Protection — PS_PROTECTION byte. Clearing it removes PPL.
    # Win8.1: 0x6aa. Win10 1507-1607: 0x6b2-0x6ca
    # Win10 1703+: 0x6fa-0x87a. Win11: 0x87a.
    {"name":  "Protection",
     "range": (0x6a0, 0x890),
     "sizes": {1},
     "primitive": "PPL_BYPASS"},

    # SignatureLevel (code integrity) — byte. Adjacent to Protection.
    # Win10 1607+: 0x6f8-0x878
    {"name":  "SignatureLevel",
     "range": (0x6f0, 0x880),
     "sizes": {1},
     "primitive": "CI_DOWNGRADE"},

    # SectionSignatureLevel — byte. Adjacent to SignatureLevel.
    {"name":  "SectionSignatureLevel",
     "range": (0x6f0, 0x880),
     "sizes": {1},
     "primitive": "CI_DOWNGRADE"},
]


def classify_eprocess_write(disp: int, size: int) -> Optional[Tuple[str, str]]:
    """Return (field_name, primitive_tag) for a write at EPROCESS+disp.

    Returns None when the offset/size doesn't match any known field —
    caller can fall back to a range-bucket tag.

    We intentionally refuse to classify offsets < 0x300 because writes
    in that range are dominated by non-EPROCESS struct fields (IRP
    IoStackLocation, DEVICE_OBJECT flags, driver-private contexts) and
    cause massive false-positive floods. The caller needs additional
    evidence (process-resolve, PsGetCurrentProcess dataflow) to treat
    low-offset writes as EPROCESS-targeted.
    """
    if disp < 0x300 or disp > 0xa00:
        return None
    for entry in EPROCESS_FIELDS:
        lo, hi = entry["range"]
        if lo <= disp <= hi and size in entry["sizes"]:
            return entry["name"], entry["primitive"]
    return None


# ──────────────────────────────────────────────────────────────────────────
# Reverse index: primitive → human-friendly name
# ──────────────────────────────────────────────────────────────────────────

PRIMITIVE_LABELS: Dict[str, str] = {
    "TOKEN_STEAL":     "token-steal",
    "PPL_BYPASS":      "ppl-bypass",
    "CI_DOWNGRADE":    "ci-downgrade",
    "PROCESS_RENAME":  "process-rename",
}
