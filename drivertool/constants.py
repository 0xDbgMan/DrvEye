"""Constants and knowledge base for Windows driver static analysis."""

from enum import IntEnum
from typing import Dict, Tuple


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

DANGEROUS_IMPORTS: Dict[str, Tuple[Severity, str, str]] = {
    # (severity, description, poc_hint)
    # Memory mapping
    "MmMapIoSpace":                (Severity.CRITICAL, "Maps physical memory — arbitrary R/W primitive if address is user-controlled", "mmap_physical"),
    "MmMapLockedPages":            (Severity.HIGH,     "Maps locked pages to user space", "mmap_physical"),
    "MmMapLockedPagesSpecifyCache":(Severity.HIGH,     "Maps locked pages with cache control", "mmap_physical"),
    "ZwMapViewOfSection":          (Severity.CRITICAL, "Maps section into process — can map kernel memory to usermode", "mmap_physical"),
    "MmCopyMemory":                (Severity.CRITICAL, "Copies arbitrary physical/virtual memory", "mmap_physical"),
    "MmCopyVirtualMemory":         (Severity.CRITICAL, "Copies memory between processes", "arbitrary_rw"),
    # Device creation
    "IoCreateDevice":              (Severity.MEDIUM,   "Creates device object — check if SecurityDescriptor is NULL", "ioctl_generic"),
    "IoCreateSymbolicLink":        (Severity.LOW,      "Creates symbolic link — check accessibility", ""),
    "IoDeleteSymbolicLink":        (Severity.LOW,      "Deletes symbolic link — racy deletion enables stale-link hijack", ""),
    "NtOpenSymbolicLinkObject":    (Severity.LOW,      "Opens symbolic link object — reconnaissance / redirection primitive", ""),
    "ZwOpenSymbolicLinkObject":    (Severity.LOW,      "Opens symbolic link object — reconnaissance / redirection primitive", ""),
    "NtQuerySymbolicLinkObject":   (Severity.LOW,      "Queries symbolic link target — often precedes redirection", ""),
    "ZwQuerySymbolicLinkObject":   (Severity.LOW,      "Queries symbolic link target — often precedes redirection", ""),
    "ObReferenceObjectByName":     (Severity.MEDIUM,   "Resolves object by name from kernel — bypasses user-mode symlink checks", ""),
    # Process manipulation
    "ZwTerminateProcess":          (Severity.HIGH,     "Can terminate arbitrary processes from kernel", "process_kill"),
    "PsLookupProcessByProcessId":  (Severity.MEDIUM,   "Resolves process by PID — often precedes manipulation", "process_lookup"),
    "KeAttachProcess":             (Severity.HIGH,     "Attaches to another process context", "process_attach"),
    "KeStackAttachProcess":        (Severity.HIGH,     "Attaches to another process context", "process_attach"),
    "ZwOpenProcess":               (Severity.MEDIUM,   "Opens handle to arbitrary process", "process_access"),
    "PsGetCurrentProcess":         (Severity.INFO,     "Gets current process — benign alone", ""),
    # Registry
    "ZwSetValueKey":               (Severity.MEDIUM,   "Writes registry values from kernel", ""),
    "ZwDeleteValueKey":            (Severity.MEDIUM,   "Deletes registry values from kernel", ""),
    "ZwCreateKey":                 (Severity.LOW,      "Creates registry keys from kernel", ""),
    # MSR / hardware
    "__readmsr":                   (Severity.CRITICAL, "Reads model-specific register", "msr_readwrite"),
    "__writemsr":                  (Severity.CRITICAL, "Writes MSR — full system compromise possible", "msr_readwrite"),
    "__readcr0":                   (Severity.HIGH,     "Reads CR0 control register", "cr_access"),
    "__writecr0":                  (Severity.CRITICAL, "Writes CR0 — can disable write protection", "cr_access"),
    "__readcr4":                   (Severity.HIGH,     "Reads CR4 control register", "cr_access"),
    "__writecr4":                  (Severity.CRITICAL, "Writes CR4 — can disable SMEP/SMAP", "cr_access"),
    "HalGetBusData":               (Severity.HIGH,     "Direct hardware bus access", ""),
    "HalSetBusData":               (Severity.HIGH,     "Direct hardware bus write", ""),
    "READ_PORT_UCHAR":             (Severity.HIGH,     "Direct I/O port read", "io_port"),
    "WRITE_PORT_UCHAR":            (Severity.HIGH,     "Direct I/O port write", "io_port"),
    "READ_PORT_USHORT":            (Severity.HIGH,     "Direct I/O port read (16-bit)", "io_port"),
    "WRITE_PORT_USHORT":           (Severity.HIGH,     "Direct I/O port write (16-bit)", "io_port"),
    "READ_PORT_ULONG":             (Severity.HIGH,     "Direct I/O port read (32-bit)", "io_port"),
    "WRITE_PORT_ULONG":            (Severity.HIGH,     "Direct I/O port write (32-bit)", "io_port"),
    # Driver loading
    "ZwLoadDriver":                (Severity.CRITICAL, "Loads arbitrary kernel driver", ""),
    "ZwUnloadDriver":              (Severity.HIGH,     "Unloads kernel driver", ""),
    # Memory allocation
    "ExAllocatePool":              (Severity.LOW,      "Pool allocation — check for size validation and NULL return", ""),
    "ExAllocatePoolWithTag":       (Severity.LOW,      "Pool allocation — check for size validation", ""),
    "ExAllocatePool2":             (Severity.LOW,      "Pool allocation (modern)", ""),
    # File operations from kernel
    "ZwCreateFile":                (Severity.MEDIUM,   "Kernel-mode file operations", ""),
    "ZwWriteFile":                 (Severity.MEDIUM,   "Kernel-mode file write", ""),
    "ZwReadFile":                  (Severity.LOW,      "Kernel-mode file read", ""),
    # Callbacks
    "PsSetCreateProcessNotifyRoutine":  (Severity.INFO, "Process creation monitoring callback", ""),
    "PsSetLoadImageNotifyRoutine":      (Severity.INFO, "Image load monitoring callback", ""),
    "CmRegisterCallback":               (Severity.INFO, "Registry monitoring callback", ""),
    "ObRegisterCallbacks":              (Severity.INFO, "Object manager callbacks", ""),
    "PsInitialSystemProcess":          (Severity.CRITICAL, "Reference to PsInitialSystemProcess — used in EPROCESS walk / token stealing", "token_steal"),
    # Callback removal
    "PsRemoveCreateThreadNotifyRoutine":     (Severity.HIGH, "Removes thread creation callback — used to blind EDR", "callback_removal"),
    "PsRemoveLoadImageNotifyRoutine":        (Severity.HIGH, "Removes image load callback — used to blind EDR", "callback_removal"),
    "CmUnRegisterCallback":                  (Severity.HIGH, "Removes registry callback — used to blind EDR", "callback_removal"),
    "ObUnRegisterCallbacks":                 (Severity.HIGH, "Removes object manager callbacks — used to blind EDR", "callback_removal"),
    "PsSetCreateProcessNotifyRoutineEx":     (Severity.INFO, "Process creation monitoring callback (Ex)", ""),
    "PsSetCreateThreadNotifyRoutine":        (Severity.INFO, "Thread creation monitoring callback", ""),
    # ETW
    "EtwRegister":                           (Severity.INFO, "Registers ETW provider", ""),
    "EtwUnregister":                         (Severity.MEDIUM, "Unregisters ETW provider", ""),
    "EtwEventWrite":                         (Severity.INFO, "Writes ETW event", ""),
    "NtTraceControl":                        (Severity.HIGH, "Controls ETW trace sessions — can disable providers", "etw_disable"),
    "ZwTraceControl":                        (Severity.HIGH, "Controls ETW trace sessions — can disable providers", "etw_disable"),
    # DSE
    "MmGetSystemRoutineAddress":             (Severity.MEDIUM, "Resolves kernel export by name — used in DSE bypass to find CI!g_CiOptions", ""),
    # Dangerous memory ops
    "ProbeForRead":                (Severity.INFO,     "Probes user buffer — positive security indicator", ""),
    "ProbeForWrite":               (Severity.INFO,     "Probes user buffer — positive security indicator", ""),
    "MmIsAddressValid":            (Severity.LOW,      "Checks address validity — often misused as security check", ""),
    "MmGetPhysicalAddress":        (Severity.HIGH,     "Gets physical address — used in physical memory access chains", "mmap_physical"),
    "MmMapIoSpaceEx":              (Severity.CRITICAL, "Maps physical memory with cache type", "mmap_physical"),
}

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

# IRP_MJ_* slot index -> name (28 slots, 0x00-0x1B)
IRP_MJ_NAMES: Dict[int, str] = {
    0x00: "IRP_MJ_CREATE",
    0x01: "IRP_MJ_CREATE_NAMED_PIPE",
    0x02: "IRP_MJ_CLOSE",
    0x03: "IRP_MJ_READ",
    0x04: "IRP_MJ_WRITE",
    0x05: "IRP_MJ_QUERY_INFORMATION",
    0x06: "IRP_MJ_SET_INFORMATION",
    0x07: "IRP_MJ_QUERY_EA",
    0x08: "IRP_MJ_SET_EA",
    0x09: "IRP_MJ_FLUSH_BUFFERS",
    0x0A: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    0x0B: "IRP_MJ_SET_VOLUME_INFORMATION",
    0x0C: "IRP_MJ_DIRECTORY_CONTROL",
    0x0D: "IRP_MJ_FILE_SYSTEM_CONTROL",
    0x0E: "IRP_MJ_DEVICE_CONTROL",
    0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    0x10: "IRP_MJ_SHUTDOWN",
    0x11: "IRP_MJ_LOCK_CONTROL",
    0x12: "IRP_MJ_CLEANUP",
    0x13: "IRP_MJ_CREATE_MAILSLOT",
    0x14: "IRP_MJ_QUERY_SECURITY",
    0x15: "IRP_MJ_SET_SECURITY",
    0x16: "IRP_MJ_POWER",
    0x17: "IRP_MJ_SYSTEM_CONTROL",
    0x18: "IRP_MJ_DEVICE_CHANGE",
    0x19: "IRP_MJ_QUERY_QUOTA",
    0x1A: "IRP_MJ_SET_QUOTA",
    0x1B: "IRP_MJ_PNP",
}

# Slots beyond IRP_MJ_DEVICE_CONTROL that are interesting attack surface
# 0x0E = IRP_MJ_DEVICE_CONTROL, 0x0F = IRP_MJ_INTERNAL_DEVICE_CONTROL
# 0x0D = IRP_MJ_FILE_SYSTEM_CONTROL (also dispatches IOCTLs for FS drivers)
IRP_MJ_INTERESTING = {0x00, 0x03, 0x04, 0x0D, 0x0E, 0x0F}

# Known vulnerable driver SHA-256 hashes.
# Empty by design — populate at runtime from a public source of truth
# (e.g. https://www.loldrivers.io/ or a mirror) rather than bundling a
# stale hash list in source. The CLI's --live-check flag pulls live
# Microsoft data; users can layer LOLDrivers data on top via --loldrivers.
LOLDRIVERS_HASHES: Dict[str, str] = {}

# -- Known-revoked / compromised code-signing certificates --
# Keys: (issuer_cn_substring, serial_hex_lowercase) or just serial_hex
# Values: description of why it's bad
# -- Kernel-trusted root certificate thumbprints (SHA-1, lowercase hex) --
# These are the roots that Windows actually trusts for kernel-mode code
# signing. A chain that does not terminate at one of these is NOT trusted
# for kernel load, regardless of any "Microsoft" substring in the CN.
#
# Categories:
#   "ms-kernel": Microsoft-issued code-signing roots (WHQL / attestation)
#   "cross-sign": Cross-signing roots Microsoft honored for kernel mode
#                 pre-2021 (expired but timestamped signatures still load)
KERNEL_TRUSTED_ROOTS: Dict[str, Tuple[str, str]] = {
    # --- Microsoft roots (current) ---
    "3b1efd3a66ea28b16697394703a72ca340a05bd5":
        ("ms-kernel", "Microsoft Root Certificate Authority 2010"),
    "8f43288ad272f3103b6fb1428485ea3014c0bcfe":
        ("ms-kernel", "Microsoft Root Certificate Authority 2011"),
    "cdd4eeae6000ac7f40c3802c171e30148030c072":
        ("ms-kernel", "Microsoft Root Certificate Authority"),
    # Microsoft Code Verification / Windows Third Party Component CA
    "31f9fc8ba3805986b721ea7295c65b3a44534274":
        ("ms-kernel", "Microsoft Code Verification Root"),
    "92c1588e85af2201ce7915e8538b492f605b80c6":
        ("ms-kernel", "Microsoft Digital Media Authority 2005"),
    # Windows Hardware Compatibility Publisher — used for attestation signing
    # (emitted via the Hardware Dev Center portal)
    "bef9c1f4d0f8e66a21e78a1c3f3d8e6e0c6e3b6e":
        ("ms-kernel", "Microsoft Windows Hardware Compatibility Publisher"),

    # --- Cross-signing roots honored pre-2021-07-01 ---
    # https://learn.microsoft.com/windows-hardware/drivers/install/
    # cross-certificates-for-kernel-mode-code-signing
    "5fb7ee0633e259dbad0c4c9ae6d38f1a61c7dc25":
        ("cross-sign", "VeriSign Class 3 Public Primary Certification Authority - G5"),
    "4eb6d578499b1ccf5f581ead56be3d9b6744a5e5":
        ("cross-sign", "VeriSign Class 3 Public Primary Certification Authority - G4"),
    "742c3192e607e424eb4549542be1bbc53e6174e2":
        ("cross-sign", "VeriSign Class 3 Public Primary Certification Authority"),
    "b1bc968bd4f49d622aa89a81f2150152a41d829c":
        ("cross-sign", "GlobalSign Root CA"),
    "75e0abb6138512271c04f85fddde38e4b7242efe":
        ("cross-sign", "GlobalSign Root CA - R3"),
    "2796bae63f1801e277261ba0d77770028f20eee4":
        ("cross-sign", "Go Daddy Class 2 Certification Authority"),
    "d1eb23a46d17d68fd92564c2f1f1601764d8e349":
        ("cross-sign", "AAA Certificate Services"),
    "273eeeac81e6cd5710eff19b7e64ffe33488373b":
        ("cross-sign", "Thawte Timestamping CA"),
    "0563b8630d62d75abbc8ab1e4bdfb5a899b24d43":
        ("cross-sign", "DigiCert Assured ID Root CA"),
    "df3c24f9bfd666761b268073fe06d1cc8d4f82a4":
        ("cross-sign", "DigiCert Global Root CA"),
    "ddfb16cd4931c973a2037d3fc83a4d7d775d05e4":
        ("cross-sign", "DigiCert Trusted Root G4"),
    "7e04de896a3e666d00e687d33ffad93be83d349e":
        ("cross-sign", "DigiCert High Assurance EV Root CA"),
    "032fa4ab20f1c71dfc5089f5d68e4ad49f0b4bb4":
        ("cross-sign", "Starfield Class 2 Certification Authority"),
    "a8985d3a65e5e5c4b2d7d66d40c6dd2fb19c5436":
        ("cross-sign", "DigiCert Assured ID Root CA (G3)"),
}

# Live thumbprint-based disallowed list populated by policy_cache from
# Microsoft's disallowedcert.stl. Mutable at runtime; the certificate
# scanner checks these in addition to KNOWN_REVOKED_CERTS. Separate sets
# by hash length — authroot.stl uses SHA-1 (20B) but disallowedcert.stl
# also carries SHA-256 (32B) entries that require SHA-256 fingerprints
# to match.
LIVE_DISALLOWED_THUMBPRINTS: set = set()       # SHA-1
LIVE_DISALLOWED_THUMBPRINTS_SHA256: set = set()

# Live Microsoft vulnerable-driver block list, parsed from the WDAC
# policy ZIP at aka.ms/VulnerableDriverBlockList. Checked in addition
# to the hardcoded MS_DRIVER_BLOCKLIST. Refreshed by --live-check.
LIVE_BLOCKED_DRIVER_HASHES_SHA1:   set = set()
LIVE_BLOCKED_DRIVER_HASHES_SHA256: set = set()

# Known-revoked / compromised code-signing certificate serials (hex).
# Empty by design — the live Microsoft disallowedcert.stl (fetched via
# --live-check) is the authoritative source of revoked thumbprints.
# Users can populate this dict with their own serial-keyed entries if
# they want per-serial descriptions in findings.
KNOWN_REVOKED_CERTS: Dict[str, str] = {}

# -- Known suspicious signer names (substring match, case-insensitive) --
SUSPICIOUS_SIGNERS = [
    ("hacking team", "HackingTeam — leaked offensive tooling cert"),
    ("ht srl", "HT Srl (HackingTeam) — revoked cert"),
    ("lapsus", "LAPSUS$ breach-related cert"),
    ("test cert", "Test/development certificate — not for production"),
    ("test sign", "Test-signed driver — Windows test mode only"),
    ("self-signed", "Self-signed certificate — no trust chain"),
    ("do not trust", "Explicitly untrusted certificate"),
    ("cheat", "Possible cheat/game-hack driver"),
    ("debug cert", "Debug/development certificate"),
    ("rootkit", "Certificate associated with rootkit software"),
    ("exploit", "Certificate associated with exploit tooling"),
    ("cobalt", "Possible Cobalt Strike — offensive tooling"),
    ("mimikatz", "Mimikatz-related certificate"),
    ("metasploit", "Metasploit-related certificate"),
    ("fivem", "FiveM mod certificate — game modification driver"),
]

# -- Microsoft Vulnerable Driver Block List (DriverSiPolicy) --
# Flat-hash SHA-256 entries from Microsoft's driver block list.
# These drivers are BLOCKED from loading by Windows Defender / Secure Boot.
# Source: Microsoft recommended driver block rules (updated periodically)
# Microsoft Vulnerable Driver Block List.
# Empty by design — use the --live-check CLI flag to fetch the
# current list directly from Microsoft (aka.ms/VulnerableDriverBlockList).
# The live list populates LIVE_BLOCKED_DRIVER_HASHES_{SHA1,SHA256} above
# and feeds the same matrix this dict does.
MS_DRIVER_BLOCKLIST: Dict[str, str] = {}

YARA_RULES_TEXT = r"""
rule RDMSR_WRMSR_Opcodes {
    strings:
        $rdmsr = { 0F 32 }
        $wrmsr = { 0F 30 }
    condition:
        uint16(0) == 0x5A4D and ($rdmsr or $wrmsr)
}
rule IO_Port_Opcodes {
    strings:
        $inb  = { EC }
        $outb = { EE }
        $ind  = { ED }
        $outd = { EF }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
rule CLI_STI_Opcodes {
    strings:
        $cli = { FA }
        $sti = { FB }
    condition:
        uint16(0) == 0x5A4D and #cli > 2 and #sti > 2
}
"""
