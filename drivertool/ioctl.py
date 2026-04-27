"""IOCTL decoding, validation, and handler-purpose mapping utilities.

Provides helpers for decoding Windows CTL_CODE-style IOCTL values,
validating whether an immediate looks like a genuine IOCTL, and mapping
IAT imports found in dispatch handlers to human-readable purpose labels.
"""

from typing import Dict, Tuple

# ── Lookup tables used by decode_ioctl ──────────────────────────────────────

IOCTL_METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

IOCTL_ACCESS_NAMES = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_DATA",
    2: "FILE_WRITE_DATA",
    3: "FILE_READ_WRITE",
}


def decode_ioctl(code: int) -> dict:
    access = (code >> 14) & 0x3
    return {
        "code":        f"0x{code:08X}",
        "device_type": (code >> 16) & 0xFFFF,
        "access":      access,
        "access_name": IOCTL_ACCESS_NAMES.get(access, "UNKNOWN"),
        "function":    (code >> 2) & 0xFFF,
        "method":      code & 0x3,
        "method_name": IOCTL_METHOD_NAMES.get(code & 0x3, "UNKNOWN"),
    }


# Common bitmask / constant values that look superficially like IOCTLs but
# are not.  Stored as a module-level frozenset so the collection is built
# once and membership tests are O(1).
_BITMASK_PATTERNS = frozenset({
    0x7FFFFFFF, 0x7FFFFFFE, 0x7FFFFFFC,
    0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFF000,
    0x80000000, 0xC0000000,
    0x000FFFFF, 0x0000FFFF, 0x00FFFFFF,
})


def is_valid_ioctl(imm: int) -> bool:
    """Check if an immediate value looks like a valid CTL_CODE-produced IOCTL."""
    device_type = (imm >> 16) & 0xFFFF
    function    = (imm >> 2)  & 0xFFF
    method      = imm & 0x3

    if device_type == 0:
        return False

    # Filter out obvious bitmasks / constants that are not real IOCTLs
    # e.g. 0x7FFFFFFF (INT_MAX), 0xFFFFF000 (page mask), 0xFFFF0000, etc.
    if imm in _BITMASK_PATTERNS:
        return False

    # Reject device_type == 0xFFFF (degenerate)
    if device_type == 0xFFFF:
        return False

    # Reject NTSTATUS error codes (0xC000XXXX) — these are not IOCTLs
    if device_type == 0xC000 and function <= 0x200:
        return False

    # Reject all-zero function with all-zero method (0xXXXX0000 alignment padding)
    if function == 0 and method == 0:
        return False

    # Reject function field == 0xFFF (all ones — looks like a mask, not a real code)
    if function == 0xFFF:
        return False

    # Real IOCTL function codes rarely exceed a few hundred.
    # Vendor codes start at 0x800, so function up to ~0xD00 is plausible.
    # Anything much higher is likely a misidentified constant.
    if function > 0xD00:
        return False

    return True


# Human-readable method name labels (short form)
IOCTL_METHOD_LABEL = {
    0: "BUFFERED",
    1: "IN_DIRECT",
    2: "OUT_DIRECT",
    3: "NEITHER",
}

# IAT function -> (purpose label, priority)
# Higher priority wins when multiple are found in the same handler tree.
HANDLER_PURPOSE_MAP: Dict[str, Tuple[str, int]] = {
    # --- Process action APIs (highest priority -- these ARE the purpose) ---
    "ZwTerminateProcess":            ("process kill",       10),
    "NtTerminateProcess":            ("process kill",       10),

    # --- Token / privilege APIs ---
    "PsInitialSystemProcess":        ("token steal",        10),
    "PsReferencePrimaryToken":       ("token steal",         9),
    "PsReferenceImpersonationToken": ("token steal",         9),
    "ZwSetInformationToken":         ("token modify",        9),
    "NtSetInformationToken":         ("token modify",        9),
    "ZwAdjustPrivilegesToken":       ("adjust privileges",   9),
    "ZwOpenProcessToken":            ("token access",        8),
    "ZwOpenProcessTokenEx":          ("token access",        8),

    # --- Memory action APIs ---
    "MmCopyVirtualMemory":           ("mem copy",            9),
    "MmCopyMemory":                  ("mem copy",            9),
    "ZwReadVirtualMemory":           ("mem read",            9),
    "NtReadVirtualMemory":           ("mem read",            9),
    "ZwWriteVirtualMemory":          ("mem write",           9),
    "NtWriteVirtualMemory":          ("mem write",           9),
    "MmMapIoSpace":                  ("phys mem map",        9),
    "MmMapIoSpaceEx":                ("phys mem map",        9),
    "ZwAllocateVirtualMemory":       ("alloc memory",        8),
    "ZwFreeVirtualMemory":           ("free memory",         8),
    "ZwProtectVirtualMemory":        ("change protection",   8),
    "ZwMapViewOfSection":            ("mem map",             8),

    # --- Thread / injection APIs ---
    "RtlCreateUserThread":           ("create thread",       9),
    "ZwCreateThreadEx":              ("create thread",       9),
    "NtCreateThreadEx":              ("create thread",       9),

    # --- CPU / hardware APIs ---
    "__writecr0":                    ("CR0 write",           9),
    "__writecr4":                    ("CR4 write",           9),
    "__writemsr":                    ("MSR write",           9),
    "__readmsr":                     ("MSR read",            8),

    # --- File action APIs ---
    "ZwDeleteFile":                  ("delete file",         8),
    "ZwWriteFile":                   ("file write",          7),
    "ZwCreateFile":                  ("file op",             5),

    # --- System query APIs ---
    "ZwQuerySystemInformation":      ("query system",        7),
    "NtQuerySystemInformation":      ("query system",        7),

    # --- Driver loading ---
    "ZwLoadDriver":                  ("load driver",         8),
    "ZwUnloadDriver":                ("unload driver",       7),

    # --- Registry ---
    "ZwSetValueKey":                 ("registry write",      7),
    "ZwDeleteKey":                   ("registry delete",     7),
    "ZwDeleteValueKey":              ("registry delete",     7),

    # --- Callback / monitor APIs ---
    "PsSetLoadImageNotifyRoutine":        ("process monitor",  6),
    "PsSetCreateProcessNotifyRoutine":    ("process monitor",  6),
    "PsSetCreateProcessNotifyRoutineEx":  ("process monitor",  6),
    "PsSetCreateThreadNotifyRoutine":     ("process monitor",  5),
    "ObRegisterCallbacks":                ("ob callback",      6),
    "CmRegisterCallback":                 ("registry monitor", 5),
    "CmRegisterCallbackEx":              ("registry monitor", 5),

    # --- Callback removal APIs (EDR blinding) ---
    "PsRemoveCreateThreadNotifyRoutine":  ("callback removal", 10),
    "PsRemoveLoadImageNotifyRoutine":     ("callback removal", 10),
    "CmUnRegisterCallback":               ("callback removal", 10),
    "ObUnRegisterCallbacks":              ("callback removal", 10),

    # --- ETW APIs ---
    "NtTraceControl":                     ("etw disable",      10),
    "ZwTraceControl":                     ("etw disable",      10),
    "EtwUnregister":                      ("etw disable",       9),
    "EtwRegister":                        ("etw register",      3),

    # --- Token downgrade APIs ---
    "NtAdjustPrivilegesToken":            ("adjust privileges", 9),

    # --- DSE / runtime resolve ---
    "MmGetSystemRoutineAddress":          ("runtime resolve",   5),

    # --- MDL / page mapping APIs ---
    "MmMapLockedPagesSpecifyCache":  ("map pages",           8),
    "MmMapLockedPages":              ("map pages",           8),
    "MmProbeAndLockPages":           ("lock pages",          7),

    # --- Process info APIs ---
    "PsGetProcessPeb":               ("get module",          7),
    "PsGetProcessWow64Process":      ("get module",          6),

    # --- Helper / setup APIs (LOW priority -- these support the action) ---
    "KeAttachProcess":               ("process attach",      4),
    "KeStackAttachProcess":          ("process attach",      4),
    "ZwOpenProcess":                 ("process access",      5),
    "PsLookupProcessByProcessId":    ("process lookup",      3),
    "PsLookupThreadByThreadId":      ("thread lookup",       3),
    "MmGetPhysicalAddress":          ("phys mem xlate",      5),
    "MmIsAddressValid":              ("validate addr",       5),
    "IoGetCurrentProcess":           ("get process",         2),
}
