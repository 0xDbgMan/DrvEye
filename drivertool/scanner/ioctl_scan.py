"""IOCTL handler analysis and structure reconstruction."""
from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import capstone.x86_const as x86c

from drivertool.constants import (
    DANGEROUS_IMPORTS, IRP_MJ_INTERESTING, IRP_MJ_NAMES, Severity,
)
from drivertool.models import Finding
from drivertool.ioctl import (
    HANDLER_PURPOSE_MAP, IOCTL_METHOD_LABEL,
    decode_ioctl, is_valid_ioctl,
)
from drivertool.ioctl_cfg import IOCTLDispatchCFG
from drivertool.dispatch_finder import DispatcherFinder
from drivertool.handler_emulator import emulate_handler
from drivertool.taint import TaintTracker

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class IOCTLScanMixin:
    """Mixin for IOCTL scanning and analysis."""

    _API_BEHAVIOR = {
        # Memory operations
        "MmMapIoSpace": ("MEMORY", "Map physical address to virtual kernel address"),
        "MmMapIoSpaceEx": ("MEMORY", "Map physical address to virtual kernel address (extended)"),
        "MmMapLockedPages": ("MEMORY", "Map locked pages into address space"),
        "MmMapLockedPagesSpecifyCache": ("MEMORY", "Map locked pages with cache type"),
        "MmUnmapIoSpace": ("MEMORY", "Unmap previously mapped physical memory"),
        "MmUnmapLockedPages": ("MEMORY", "Unmap previously locked pages"),
        "MmCopyVirtualMemory": ("MEMORY", "Copy between virtual address spaces (cross-process)"),
        "MmCopyMemory": ("MEMORY", "Copy from physical or virtual memory"),
        "MmGetPhysicalAddress": ("MEMORY", "Translate virtual to physical address"),
        "MmAllocateContiguousMemory": ("MEMORY", "Allocate contiguous physical memory"),
        "MmAllocateContiguousMemorySpecifyCache": ("MEMORY", "Allocate contiguous with cache spec"),
        "MmProbeAndLockPages": ("MEMORY", "Probe and lock user pages into physical memory"),
        "MmUnlockPages": ("MEMORY", "Unlock previously locked pages"),
        "MmGetSystemAddressForMdlSafe": ("MEMORY", "Get kernel VA from MDL"),
        "ZwMapViewOfSection": ("MEMORY", "Map section view into address space"),
        "ZwUnmapViewOfSection": ("MEMORY", "Unmap section view"),
        "ZwAllocateVirtualMemory": ("MEMORY", "Allocate virtual memory in process"),
        "ZwFreeVirtualMemory": ("MEMORY", "Free virtual memory in process"),
        "ZwReadVirtualMemory": ("MEMORY", "Read from process virtual memory"),
        "ZwWriteVirtualMemory": ("MEMORY", "Write to process virtual memory"),
        "NtReadVirtualMemory": ("MEMORY", "Read from process virtual memory"),
        "NtWriteVirtualMemory": ("MEMORY", "Write to process virtual memory"),
        # Pool
        "ExAllocatePool": ("POOL", "Allocate kernel pool memory (legacy)"),
        "ExAllocatePoolWithTag": ("POOL", "Allocate tagged kernel pool memory"),
        "ExAllocatePool2": ("POOL", "Allocate kernel pool memory (modern)"),
        "ExAllocatePool3": ("POOL", "Allocate kernel pool memory (extended)"),
        "ExFreePool": ("POOL", "Free kernel pool memory"),
        "ExFreePoolWithTag": ("POOL", "Free tagged kernel pool memory"),
        # Process
        "PsLookupProcessByProcessId": ("PROCESS", "Lookup EPROCESS by PID"),
        "PsLookupThreadByThreadId": ("PROCESS", "Lookup ETHREAD by TID"),
        "KeAttachProcess": ("PROCESS", "Attach to process address space"),
        "KeStackAttachProcess": ("PROCESS", "Attach to process (stack-safe)"),
        "KeDetachProcess": ("PROCESS", "Detach from process address space"),
        "KeUnstackDetachProcess": ("PROCESS", "Detach from process (stack-safe)"),
        "ZwOpenProcess": ("PROCESS", "Open handle to process"),
        "NtOpenProcess": ("PROCESS", "Open handle to process"),
        "ZwTerminateProcess": ("PROCESS", "Terminate a process"),
        "NtTerminateProcess": ("PROCESS", "Terminate a process"),
        "PsGetCurrentProcessId": ("PROCESS", "Get current process ID"),
        "PsGetCurrentProcess": ("PROCESS", "Get current EPROCESS pointer"),
        "PsGetProcessId": ("PROCESS", "Get PID from EPROCESS"),
        "ZwOpenThread": ("PROCESS", "Open handle to thread"),
        "ZwSuspendThread": ("PROCESS", "Suspend a thread"),
        "ZwResumeThread": ("PROCESS", "Resume a thread"),
        "ZwSetInformationThread": ("PROCESS", "Set thread information"),
        # Token / Privilege
        "PsReferencePrimaryToken": ("TOKEN", "Reference process primary token"),
        "PsReferenceImpersonationToken": ("TOKEN", "Reference thread impersonation token"),
        "SePrivilegeCheck": ("TOKEN", "Check if token has privilege"),
        "SeSinglePrivilegeCheck": ("TOKEN", "Check single privilege"),
        "SeAccessCheck": ("TOKEN", "Perform access check against SD"),
        "SeLookupPrivilegeValue": ("TOKEN", "Lookup privilege LUID"),
        "ZwSetInformationToken": ("TOKEN", "Modify token information"),
        "NtSetInformationToken": ("TOKEN", "Modify token information"),
        "ZwOpenProcessToken": ("TOKEN", "Open process token"),
        "ZwOpenProcessTokenEx": ("TOKEN", "Open process token (extended)"),
        "ZwAdjustPrivilegesToken": ("TOKEN", "Adjust token privileges"),
        # Object
        "ObReferenceObjectByHandle": ("OBJECT", "Reference kernel object from handle"),
        "ObReferenceObjectByPointer": ("OBJECT", "Reference kernel object from pointer"),
        "ObDereferenceObject": ("OBJECT", "Dereference kernel object"),
        "ObOpenObjectByPointer": ("OBJECT", "Open handle from kernel pointer"),
        "ZwClose": ("OBJECT", "Close kernel handle"),
        # Registry
        "ZwOpenKey": ("REGISTRY", "Open registry key"),
        "ZwCreateKey": ("REGISTRY", "Create registry key"),
        "ZwSetValueKey": ("REGISTRY", "Write registry value"),
        "ZwQueryValueKey": ("REGISTRY", "Read registry value"),
        "ZwDeleteKey": ("REGISTRY", "Delete registry key"),
        "ZwDeleteValueKey": ("REGISTRY", "Delete registry value"),
        "ZwEnumerateKey": ("REGISTRY", "Enumerate registry subkeys"),
        "ZwEnumerateValueKey": ("REGISTRY", "Enumerate registry values"),
        # File
        "ZwCreateFile": ("FILE", "Create or open file"),
        "ZwReadFile": ("FILE", "Read from file"),
        "ZwWriteFile": ("FILE", "Write to file"),
        "ZwDeleteFile": ("FILE", "Delete a file"),
        "ZwQueryInformationFile": ("FILE", "Query file information"),
        "ZwSetInformationFile": ("FILE", "Set file information"),
        # CPU special
        "__readmsr": ("CPU", "Read Model Specific Register"),
        "__writemsr": ("CPU", "Write Model Specific Register"),
        "_readmsr": ("CPU", "Read Model Specific Register"),
        "_writemsr": ("CPU", "Write Model Specific Register"),
        "__readcr0": ("CPU", "Read Control Register 0"),
        "__writecr0": ("CPU", "Write Control Register 0 (disable WP)"),
        "__readcr3": ("CPU", "Read Control Register 3 (page table base)"),
        "__writecr3": ("CPU", "Write Control Register 3"),
        "__readcr4": ("CPU", "Read Control Register 4"),
        "__writecr4": ("CPU", "Write Control Register 4"),
        "HalSetBusData": ("IO", "Write to PCI/hardware bus"),
        "HalGetBusData": ("IO", "Read from PCI/hardware bus"),
        "__indword": ("IO", "Read DWORD from I/O port"),
        "__outdword": ("IO", "Write DWORD to I/O port"),
        "__inbyte": ("IO", "Read byte from I/O port"),
        "__outbyte": ("IO", "Write byte to I/O port"),
        # Probe / validation
        "ProbeForRead": ("VALIDATION", "Validate user buffer for reading"),
        "ProbeForWrite": ("VALIDATION", "Validate user buffer for writing"),
        "ExGetPreviousMode": ("VALIDATION", "Get caller's processor mode"),
        "KeGetPreviousMode": ("VALIDATION", "Get caller's processor mode"),
        # Driver / callback
        "PsSetLoadImageNotifyRoutine": ("CALLBACK", "Register image load callback"),
        "PsSetCreateProcessNotifyRoutine": ("CALLBACK", "Register process create callback"),
        "PsSetCreateThreadNotifyRoutine": ("CALLBACK", "Register thread create callback"),
        "CmRegisterCallback": ("CALLBACK", "Register registry callback"),
        "CmRegisterCallbackEx": ("CALLBACK", "Register registry callback (extended)"),
        "ObRegisterCallbacks": ("CALLBACK", "Register object operation callbacks"),
        "FltRegisterFilter": ("CALLBACK", "Register minifilter"),
        "PsRemoveCreateThreadNotifyRoutine": ("CALLBACK", "Remove thread creation callback"),
        "PsRemoveLoadImageNotifyRoutine": ("CALLBACK", "Remove image load callback"),
        "CmUnRegisterCallback": ("CALLBACK", "Remove registry callback"),
        "ObUnRegisterCallbacks": ("CALLBACK", "Remove object manager callbacks"),
        # ETW
        "EtwRegister": ("ETW", "Register ETW provider"),
        "EtwUnregister": ("ETW", "Unregister ETW provider"),
        "EtwEventWrite": ("ETW", "Write ETW event"),
        "NtTraceControl": ("ETW", "Control ETW trace session"),
        "ZwTraceControl": ("ETW", "Control ETW trace session"),
        "EtwEventEnabled": ("ETW", "Check if ETW event is enabled"),
        # DSE / CI
        "MmGetSystemRoutineAddress": ("DRIVER", "Resolve kernel export by name at runtime"),
        "ZwLoadDriver": ("DRIVER", "Load a kernel driver"),
        "ZwUnloadDriver": ("DRIVER", "Unload a kernel driver"),
        # IRP completion
        "IoCompleteRequest": ("IRP", "Complete an IRP"),
        "IofCompleteRequest": ("IRP", "Complete an IRP (fast)"),
        "IoCallDriver": ("IRP", "Forward IRP to lower driver"),
        "IofCallDriver": ("IRP", "Forward IRP to lower driver (fast)"),
        # Synchronization
        "KeInitializeSpinLock": ("SYNC", "Initialize spin lock"),
        "KeAcquireSpinLock": ("SYNC", "Acquire spin lock"),
        "KeReleaseSpinLock": ("SYNC", "Release spin lock"),
        "ExAcquireFastMutex": ("SYNC", "Acquire fast mutex"),
        "ExReleaseFastMutex": ("SYNC", "Release fast mutex"),
        "KeWaitForSingleObject": ("SYNC", "Wait on kernel object"),
        "KeSetEvent": ("SYNC", "Signal an event"),
        # Thread creation
        "RtlCreateUserThread": ("PROCESS", "Create user-mode thread in process"),
        "ZwCreateThreadEx": ("PROCESS", "Create thread in process (extended)"),
        "NtCreateThreadEx": ("PROCESS", "Create thread in process (extended)"),
        # Memory protection
        "ZwProtectVirtualMemory": ("MEMORY", "Change virtual memory protection"),
        "NtProtectVirtualMemory": ("MEMORY", "Change virtual memory protection"),
        # System query
        "ZwQuerySystemInformation": ("PROCESS", "Query system information (process list, etc.)"),
        "NtQuerySystemInformation": ("PROCESS", "Query system information (process list, etc.)"),
        "ZwQueryInformationProcess": ("PROCESS", "Query process information"),
        "NtQueryInformationProcess": ("PROCESS", "Query process information"),
        # Process info
        "PsGetProcessPeb": ("PROCESS", "Get process PEB (module info)"),
        "PsGetProcessWow64Process": ("PROCESS", "Get WOW64 PEB for 32-bit process"),
        "IoGetCurrentProcess": ("PROCESS", "Get current EPROCESS pointer"),
        # Address validation
        "MmIsAddressValid": ("VALIDATION", "Check if virtual address is valid"),
        # Token / privilege (additional)
        "NtAdjustPrivilegesToken": ("TOKEN", "Adjust token privileges"),
        "ZwDuplicateToken": ("TOKEN", "Duplicate an access token"),
        "NtDuplicateToken": ("TOKEN", "Duplicate an access token"),
        # Data imports (loaded via mov/lea, not call)
        "PsInitialSystemProcess": ("TOKEN", "SYSTEM EPROCESS pointer — used for token steal"),
    }

    def scan_ioctl_handler(self):
        ep_addr, ep_bytes = self.pe.get_entry_point_bytes(count=4096)
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        # ── Extract all MajorFunction slots from DriverEntry ──────────────
        major_funcs: Dict[int, int] = {}
        if ep_bytes:
            major_funcs = self.dis.extract_major_functions(
                ep_bytes, ep_addr, image_base)

        if not major_funcs:
            # Try WDF detection before falling back to brute-force
            if self._try_wdf_dispatch():
                return

            # Fallback 2: scan all code sections for dispatcher signatures
            # (jump tables, cmp chains, IOS field loads)
            finder = DispatcherFinder(self.pe, self.dis)
            candidates = finder.find_candidates()
            dispatch_found = False
            for disp_va, confidence in candidates[:3]:
                logger.debug(
                    "DispatcherFinder candidate: 0x%X (confidence %.1f)",
                    disp_va, confidence)
                cfg = IOCTLDispatchCFG(self.pe, self.dis)
                ioctl_map = cfg.reconstruct(disp_va)
                if ioctl_map and len(ioctl_map) >= 2:
                    self._analyze_from_ioctl_map(ioctl_map, disp_va, slot=0x0E)
                    self._try_reverse_hash_dispatch(
                        list(ioctl_map.keys()), slot=0x0E)
                    dispatch_found = True
                    # Don't return — merge with bruteforce to catch any
                    # out-of-line or non-table IOCTLs the driver may also use.
                    break

            # Fallback 3: pure brute-force constant scan — ALWAYS run so we
            # don't miss IOCTLs that DispatcherFinder / IOCTLDispatchCFG
            # failed to recover.
            self._scan_ioctl_codes_bruteforce()
            self._resolve_bruteforce_purposes()
            return

        # ── Report all interesting slots ──────────────────────────────────
        for slot, hva in sorted(major_funcs.items()):
            slot_name = IRP_MJ_NAMES.get(slot, f"IRP_MJ_slot_{slot:#x}")
            self.findings.append(Finding(
                title=f"{slot_name} handler at 0x{hva:X}",
                severity=Severity.INFO,
                description=f"MajorFunction[{slot:#x}] ({slot_name}) set in DriverEntry",
                location=f"0x{hva:X}",
                details={"slot": f"{slot:#x}", "slot_name": slot_name,
                         "handler": f"0x{hva:X}"},
            ))

        # ── Analyse IRP_MJ_DEVICE_CONTROL and other interesting slots ─────
        for slot in sorted(major_funcs):
            if slot not in IRP_MJ_INTERESTING:
                continue
            hva = major_funcs[slot]
            slot_name = IRP_MJ_NAMES.get(slot, f"slot_{slot:#x}")

            if slot in (0x0D, 0x0E, 0x0F):
                # DEVICE_CONTROL / INTERNAL_DEVICE_CONTROL / FS_CONTROL
                # — full IOCTL CFG reconstruction. Slot is carried forward so
                # codes can be tagged FSCTL vs IOCTL in the output.
                cfg = IOCTLDispatchCFG(self.pe, self.dis)
                ioctl_map = cfg.reconstruct(hva)
                if ioctl_map:
                    self._analyze_from_ioctl_map(ioctl_map, hva, slot=slot)
                    # Hash-dispatch reversal — if the discovered constants
                    # don't look like real CTL_CODEs, the dispatcher may be
                    # comparing hashes. Try to invert them.
                    self._try_reverse_hash_dispatch(
                        list(ioctl_map.keys()), slot=slot)
                else:
                    rva = hva - image_base
                    data = self.pe.get_bytes_at_rva(rva, 16384)
                    if data:
                        insns = self.dis.disassemble_function(
                            data, hva, max_insns=1200)
                        self._analyze_ioctl_handler(insns, hva, slot=slot)
            else:
                # READ/WRITE/CREATE — scan the handler body for dangerous calls
                self._analyze_irp_handler(hva, slot_name)

    def _analyze_ioctl_handler(self, insns: list, base: int, slot: int = 0x0E):
        ioctl_codes = []
        has_probe = False

        # Resolve call targets to import names
        call_targets = self.dis.find_all_call_targets(insns)
        called_funcs = set()
        for _, target in call_targets:
            if target in self.pe.iat_map:
                called_funcs.add(self.pe.iat_map[target])

        if "ProbeForRead" in called_funcs or "ProbeForWrite" in called_funcs:
            has_probe = True

        # Extract IOCTL codes from CMP instructions
        # Also look for the conditional jump right after each CMP to find the handler VA
        for i, insn in enumerate(insns):
            if insn.mnemonic in ("cmp", "sub") and len(insn.operands) == 2:
                op = insn.operands[1]
                if op.type == x86c.X86_OP_IMM:
                    imm = op.imm & 0xFFFFFFFF
                    if 0x80000 <= imm <= 0xFFFFFFFF and (imm & 0x3) <= 3:
                        device_type = (imm >> 16) & 0xFFFF
                        if device_type > 0:
                            # Look ahead up to 4 instructions for JE/JZ to the handler
                            handler_va = None
                            for j in range(i + 1, min(i + 5, len(insns))):
                                ji = insns[j]
                                if ji.mnemonic in ("je", "jz") and ji.operands:
                                    jop = ji.operands[0]
                                    if jop.type == x86c.X86_OP_IMM:
                                        handler_va = jop.imm
                                        break
                                # Stop at another CMP or unconditional JMP
                                if ji.mnemonic in ("cmp", "jmp"):
                                    break
                            ioctl_codes.append((insn.address, imm, handler_va))

        # Build handler VA bounds for purpose detection
        handler_vas_sorted = sorted(set(
            hva for _, _, hva in ioctl_codes if hva is not None))
        handler_bounds: Dict[int, int] = {}
        for idx, hva in enumerate(handler_vas_sorted):
            if idx + 1 < len(handler_vas_sorted):
                nxt = handler_vas_sorted[idx + 1]
                if 0 < (nxt - hva) < 0x400:
                    handler_bounds[hva] = nxt

        for addr, code, handler_va in ioctl_codes:
            decoded = decode_ioctl(code)
            method = code & 0x3
            # Track all real IOCTL codes found
            if code not in self.ioctl_codes:
                self.ioctl_codes.append(code)
            self.ioctl_origin_slot[code] = slot
            # Try to determine what the handler does
            if handler_va and code not in self.ioctl_purposes:
                ma = handler_bounds.get(handler_va, 0)
                purpose = self._get_ioctl_purpose(handler_va, max_addr=ma)
                if purpose:
                    self.ioctl_purposes[code] = purpose

            if method == 3:  # METHOD_NEITHER
                self.findings.append(Finding(
                    title=f"IOCTL {decoded['code']} uses METHOD_NEITHER",
                    severity=Severity.CRITICAL if not has_probe else Severity.HIGH,
                    description="METHOD_NEITHER passes raw user-mode pointers to the driver. "
                                "Without ProbeForRead/ProbeForWrite, this enables arbitrary "
                                "kernel read/write from usermode.",
                    location=f"0x{addr:X}",
                    poc_hint="ioctl_method_neither",
                    ioctl_code=code,
                    details={
                        "ioctl_code": decoded["code"],
                        "method": "METHOD_NEITHER",
                        "device_type": f"0x{decoded['device_type']:X}",
                        "function": f"0x{decoded['function']:X}",
                        "has_probe": str(has_probe),
                        **({"handler": f"0x{handler_va:X}"} if handler_va else {}),
                    },
                ))
            else:
                self.findings.append(Finding(
                    title=f"IOCTL {decoded['code']} ({decoded['method_name']})",
                    severity=Severity.INFO,
                    description=f"IOCTL handler processes code {decoded['code']}",
                    location=f"0x{addr:X}",
                    poc_hint="ioctl_generic",
                    ioctl_code=code,
                    details={
                        "ioctl_code": decoded["code"],
                        "method": decoded["method_name"],
                        **({"handler": f"0x{handler_va:X}"} if handler_va else {}),
                    },
                ))

        if ioctl_codes and not has_probe:
            self.findings.append(Finding(
                title="IOCTL handler lacks ProbeForRead/ProbeForWrite",
                severity=Severity.HIGH,
                description="No calls to ProbeForRead or ProbeForWrite found in "
                            "the IOCTL handler. User buffer access may be unvalidated.",
                location=f"Handler at 0x{base:X}",
                poc_hint="ioctl_no_probe",
            ))

    def _try_reverse_hash_dispatch(self, candidate_codes: List[int],
                                    slot: int = 0x0E) -> None:
        """If the dispatcher's switch constants look like hash values
        rather than real CTL_CODEs, brute-force candidate IOCTL codes
        through known hash functions to recover the originals.

        Results are appended to ``self.ioctl_codes``,
        ``self.ioctl_origin_slot`` and ``self.hash_dispatch_codes``.
        """
        from drivertool import hash_dispatch as _hd
        if not candidate_codes or not _hd.looks_like_hashes(candidate_codes):
            return
        target_hashes = set(candidate_codes)
        recovered = _hd.reverse_hashed_codes(target_hashes)
        for real_code, (hash_name, hash_val) in recovered.items():
            if real_code in self.ioctl_codes:
                continue
            self.ioctl_codes.append(real_code)
            self.ioctl_origin_slot[real_code] = slot
            self.hash_dispatch_codes.append(real_code)
            self.findings.append(Finding(
                title=f"Recovered hash-dispatched IOCTL {decode_ioctl(real_code)['code']}",
                severity=Severity.HIGH,
                description=(f"Dispatcher compared {hash_name}(ioctl_code) against "
                             f"0x{hash_val:08X}. Brute-forcing the 32-bit IOCTL "
                             f"space through {hash_name} matched the real code "
                             f"{decode_ioctl(real_code)['code']}. This pattern is "
                             "a deliberate anti-RE obfuscation — treat the "
                             "recovered code as a real attack surface entry."),
                location=f"dispatch slot 0x{slot:02X}",
                details={
                    "real_code": f"0x{real_code:08X}",
                    "hash_fn":   hash_name,
                    "hash_val":  f"0x{hash_val:08X}",
                },
            ))

    def _analyze_from_ioctl_map(self, ioctl_map: Dict[int, int], dispatch_addr: int,
                                 slot: int = 0x0E):
        """
        Process the precise {ioctl_code: handler_va} map from IOCTLDispatchCFG.
        Annotates each IOCTL with its purpose and emits findings.
        Optionally emulates each handler to confirm reachable API calls.
        """
        has_probe = False
        for handler_va in ioctl_map.values():
            handler_rva = handler_va - self.pe.pe.OPTIONAL_HEADER.ImageBase
            handler_bytes = self.pe.get_bytes_at_rva(handler_rva, 4096)
            if not handler_bytes:
                continue
            insns = self.dis.disassemble_function(handler_bytes, handler_va, max_insns=200)
            for _, target in self.dis.find_all_call_targets(insns):
                fn = self.pe.iat_map.get(target, "")
                if fn in ("ProbeForRead", "ProbeForWrite"):
                    has_probe = True
                    break
            if has_probe:
                break

        # Build sorted handler VA list for bounding each case block
        sorted_items = sorted(ioctl_map.items())
        handler_vas_sorted = [va for _, va in sorted_items]

        for idx, (code, handler_va) in enumerate(sorted_items):
            decoded = decode_ioctl(code)
            method  = code & 0x3
            access  = decoded["access"]

            if code not in self.ioctl_codes:
                self.ioctl_codes.append(code)
            self.ioctl_origin_slot[code] = slot
            if code not in self.ioctl_purposes:
                # Bound disassembly to next handler's VA to prevent bleed
                next_va = handler_vas_sorted[idx + 1] if idx + 1 < len(handler_vas_sorted) else 0
                # Only bound if next handler is nearby (same switch block)
                max_addr = next_va if next_va and 0 < (next_va - handler_va) < 0x400 else 0
                purpose = self._get_ioctl_purpose(handler_va, max_addr=max_addr)
                if purpose:
                    self.ioctl_purposes[code] = purpose

            purpose_label = self.ioctl_purposes.get(code)
            purpose_str   = f" → {purpose_label}" if purpose_label else ""
            access_str    = decoded["access_name"]

            # FILE_ANY_ACCESS + METHOD_NEITHER = worst case: any user, raw pointer
            if method == 3 and access == 0:
                sev = Severity.CRITICAL
                desc = ("METHOD_NEITHER + FILE_ANY_ACCESS: raw user-mode pointer "
                        "passed to kernel, callable by any unprivileged user handle.")
            elif method == 3:
                sev = Severity.CRITICAL if not has_probe else Severity.HIGH
                desc = ("METHOD_NEITHER passes raw user-mode pointers to the driver. "
                        "Without ProbeForRead/ProbeForWrite, this enables arbitrary "
                        "kernel read/write from usermode.")
            else:
                sev = Severity.INFO
                desc = f"IOCTL dispatch → handler at 0x{handler_va:X}"

            # ── Dynamic validation via emulation ────────────────────────
            emu_hits: List[str] = []
            if method == 3 or sev >= Severity.HIGH:
                try:
                    er = emulate_handler(self.pe, handler_va, code)
                    if not er.unavailable:
                        emu_hits = [h["name"] for h in er.api_hits]
                        logger.debug(
                            "Emulated IOCTL 0x%08X @ 0x%X: %d hits (%s)",
                            code, handler_va, len(emu_hits),
                            ", ".join(emu_hits) if emu_hits else "none")
                except Exception:
                    logger.debug("Emulation failed for 0x%08X", code, exc_info=True)

            self.findings.append(Finding(
                title=(f"IOCTL {decoded['code']} ({decoded['method_name']}, "
                       f"{access_str}){purpose_str}"),
                severity=sev,
                description=desc,
                location=f"0x{handler_va:X}",
                poc_hint="ioctl_method_neither" if method == 3 else "ioctl_generic",
                ioctl_code=code,
                details={
                    "ioctl_code":   decoded["code"],
                    "method":       decoded["method_name"],
                    "access":       access_str,
                    "device_type":  f"0x{decoded['device_type']:X}",
                    "function":     f"0x{decoded['function']:X}",
                    "handler":      f"0x{handler_va:X}",
                    "has_probe":    str(has_probe),
                    "emu_hits":     ", ".join(emu_hits) if emu_hits else "",
                },
            ))

            # Extra finding: FILE_ANY_ACCESS means unprivileged callers
            if access == 0 and sev >= Severity.HIGH:
                self.findings.append(Finding(
                    title=f"IOCTL {decoded['code']} callable by any user (FILE_ANY_ACCESS)",
                    severity=Severity.HIGH,
                    description="Access field is FILE_ANY_ACCESS (0). Any process that "
                                "opens the device with any access right can send this IOCTL. "
                                "No elevated privilege required.",
                    location=f"0x{handler_va:X}",
                    ioctl_code=code,
                    details={"ioctl_code": decoded["code"], "access": access_str},
                ))

        if ioctl_map and not has_probe:
            self.findings.append(Finding(
                title="IOCTL handler lacks ProbeForRead/ProbeForWrite",
                severity=Severity.HIGH,
                description="No calls to ProbeForRead or ProbeForWrite found in "
                            "any IOCTL handler. User buffer access may be unvalidated.",
                location=f"Dispatch at 0x{dispatch_addr:X}",
                poc_hint="ioctl_no_probe",
            ))

    def _try_wdf_dispatch(self) -> bool:
        """
        Detect WDF (Windows Driver Framework) based drivers.
        WDF drivers use WdfDriverCreate/WdfIoQueueCreate instead of
        DriverObject->MajorFunction[].  The EvtIoDeviceControl callback
        is passed in the queue config struct.

        Returns True if WDF was detected and at least partial analysis done.
        """
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]
        wdf_markers = ("WdfVersionBind", "WdfDriverCreate", "WdfDeviceCreate",
                       "WdfIoQueueCreate", "WdfDeviceCreateDeviceInterface")
        found = [m for m in wdf_markers if m in all_imports]
        if not found:
            return False

        self.findings.append(Finding(
            title="WDF (Windows Driver Framework) driver detected",
            severity=Severity.INFO,
            description=f"Driver uses WDF framework (detected imports: {', '.join(found)}). "
                        "IOCTL dispatch uses EvtIoDeviceControl callback via WdfIoQueueCreate "
                        "rather than DriverObject->MajorFunction[].",
            location="Import Table",
            details={"wdf_imports": ", ".join(found)},
        ))

        # ── Locate the EvtIoDeviceControl callback ──────────────────────────
        # Signature (x64):  void Evt(WDFQUEUE, WDFREQUEST, size_t out, size_t in, ULONG IoControlCode)
        # The 5th arg (IoControlCode) lives at [rsp + 0x28] inside the
        # callee. EvtIoDeviceControl handlers therefore typically begin
        # with `mov <reg32>, [rsp + 0x28]` shortly after the prologue,
        # then dispatch on that register via cmp/sub-chain — exactly what
        # IOCTLDispatchCFG already understands.
        evt_candidates = self._find_wdf_evt_io_devcontrol()

        ran_cfg = False
        for fn_va in evt_candidates:
            cfg = IOCTLDispatchCFG(self.pe, self.dis)
            ioctl_map = cfg.reconstruct(fn_va)
            if ioctl_map:
                self.findings.append(Finding(
                    title=f"WDF EvtIoDeviceControl handler at 0x{fn_va:X}",
                    severity=Severity.INFO,
                    description=f"Detected EvtIoDeviceControl callback (loads "
                                f"IoControlCode from [rsp+0x28]). "
                                f"{len(ioctl_map)} IOCTL(s) dispatched.",
                    location=f"0x{fn_va:X}",
                    details={"handler": f"0x{fn_va:X}",
                             "ioctl_count": str(len(ioctl_map))},
                ))
                self._analyze_from_ioctl_map(ioctl_map, fn_va)
                ran_cfg = True

        # If the targeted lookup found nothing usable, fall back to the
        # brute-force scan so we still surface IOCTL constants.
        if not ran_cfg:
            self._scan_ioctl_codes_bruteforce()
            self._resolve_bruteforce_purposes()

        return True

    def _find_wdf_evt_io_devcontrol(self) -> List[int]:
        """Return function VAs that match the EvtIoDeviceControl signature.

        Heuristic: look in the first ~30 instructions for a load from
        [rsp + 0x28] (5th argument under the x64 calling convention).
        We additionally require that the function contains at least one
        cmp-with-immediate or sub-with-immediate that looks like an IOCTL
        comparison (immediate >= 0x10000, valid CTL_CODE bits).
        """
        results: List[int] = []
        seen: set = set()
        for sec_va, sec_data in self.pe.get_code_sections():
            for fn_va in self.dis.find_function_prologues(sec_va, sec_data):
                if fn_va in seen:
                    continue
                seen.add(fn_va)
                rva = fn_va - self.pe.pe.OPTIONAL_HEADER.ImageBase
                data = self.pe.get_bytes_at_rva(rva, 2048)
                if not data:
                    continue
                insns = self.dis.disassemble_function(
                    data, fn_va, max_insns=60)

                loads_arg5 = False
                for insn in insns[:30]:
                    if insn.mnemonic != "mov" or len(insn.operands) != 2:
                        continue
                    d, s = insn.operands
                    if (d.type == x86c.X86_OP_REG and
                            s.type == x86c.X86_OP_MEM and
                            s.mem.base == x86c.X86_REG_RSP and
                            s.mem.index == 0 and s.mem.disp == 0x28):
                        loads_arg5 = True
                        break
                if not loads_arg5:
                    continue

                has_ioctl_compare = False
                for insn in insns:
                    if insn.mnemonic in ("cmp", "sub") and len(insn.operands) == 2:
                        op0, op1 = insn.operands
                        if (op0.type == x86c.X86_OP_REG and
                                op1.type == x86c.X86_OP_IMM and
                                is_valid_ioctl(op1.imm & 0xFFFFFFFF)):
                            has_ioctl_compare = True
                            break
                if has_ioctl_compare:
                    results.append(fn_va)
        return results

    def _analyze_irp_handler(self, handler_va: int, slot_name: str):
        """
        Analyse a non-DEVICE_CONTROL IRP handler (READ, WRITE, CREATE …).
        Reports dangerous calls found inside the handler body.
        """
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        rva = handler_va - image_base
        data = self.pe.get_bytes_at_rva(rva, 4096)
        if not data:
            return

        insns = self.dis.disassemble_function(data, handler_va, max_insns=300)
        dangerous: List[str] = []
        for _, target in self.dis.find_all_call_targets(insns):
            fn = self.pe.iat_map.get(target, "")
            if fn and fn in HANDLER_PURPOSE_MAP:
                label, _ = HANDLER_PURPOSE_MAP[fn]
                if fn not in dangerous:
                    dangerous.append(fn)

        if dangerous:
            self.findings.append(Finding(
                title=f"{slot_name} handler calls dangerous API: {', '.join(dangerous)}",
                severity=Severity.HIGH,
                description=f"{slot_name} handler at 0x{handler_va:X} directly calls "
                            f"sensitive kernel APIs: {', '.join(dangerous)}. "
                            "This handler may be reachable via IRP without IOCTL codes.",
                location=f"0x{handler_va:X}",
                poc_hint="ioctl_generic",
                details={"handler": f"0x{handler_va:X}",
                         "slot": slot_name,
                         "calls": ", ".join(dangerous)},
            ))

    def _scan_ioctl_codes_bruteforce(self):
        """
        Fallback: scan all code sections for IOCTL-like constants.

        Handles dispatch patterns:
          1. CMP reg, IOCTL_CODE / JE handler
          2. SUB reg, IOCTL_BASE / JE handler / SUB reg, N / JE handler2 / ...
             (accumulating subtraction chains where each SUB adds to the running IOCTL)
          3. CMP reg, N / JE handler  (at end of SUB chain, final diff check)
          4. AND reg, mask / CMP reg, value (compiler masks then compares)
          5. MOVZX + CMP patterns (byte/word comparisons from switch tables)
          6. TEST reg, imm / JNZ (bit-flag IOCTL dispatch)
        """
        seen: set = set()
        for va, data in self.pe.get_code_sections():
            insns = list(self.dis.disassemble_range(data, va, max_insns=30000))
            i = 0
            while i < len(insns):
                insn = insns[i]
                # Look for SUB/CMP with IOCTL-sized immediate
                # Accept: reg, imm (dispatch) or [reg+0x18], imm (direct IOS comparison)
                # Reject: [reg+other], imm (likely signature/magic checks)
                if insn.mnemonic in ("cmp", "sub") and len(insn.operands) >= 2:
                    dst_op = insn.operands[0]
                    op = insn.operands[-1]
                    if op.type != x86c.X86_OP_IMM:
                        i += 1
                        continue
                    # Filter: must be register, memory at offset 0x18
                    # (IO_STACK_LOCATION->Parameters.DeviceIoControl.IoControlCode),
                    # or stack-relative (compiler may cache IOCTL code in a local var)
                    valid_dst = False
                    if dst_op.type == x86c.X86_OP_REG:
                        valid_dst = True
                    elif dst_op.type == x86c.X86_OP_MEM and dst_op.mem.index == 0:
                        base_reg_id = dst_op.mem.base
                        disp = dst_op.mem.disp
                        # Direct IOS field access
                        if disp in (0x18, 0x10):
                            valid_dst = True
                        # Stack-relative: [rsp+X] or [rbp+/-X] (local variable)
                        elif base_reg_id in (x86c.X86_REG_RSP, x86c.X86_REG_RBP,
                                             x86c.X86_REG_ESP, x86c.X86_REG_EBP):
                            valid_dst = True
                    if valid_dst:
                        imm = op.imm & 0xFFFFFFFF
                        if is_valid_ioctl(imm) and imm not in seen:
                            # Found a base IOCTL code
                            base_reg = dst_op
                            is_sub_chain = (insn.mnemonic == "sub")

                            # Register this IOCTL
                            self._register_bruteforce_ioctl(
                                imm, insn.address, insns, i, seen)

                            # If this is SUB, follow the subtraction chain
                            if is_sub_chain:
                                acc = imm
                                j = i + 1
                                while j < min(i + 80, len(insns)):
                                    ji = insns[j]
                                    # Skip JE/JZ (handler jumps)
                                    if ji.mnemonic in ("je", "jz", "jne", "jnz"):
                                        j += 1
                                        continue
                                    # Another SUB with small immediate = next IOCTL in chain
                                    if ji.mnemonic == "sub" and len(ji.operands) == 2:
                                        sop = ji.operands[1]
                                        if sop.type == x86c.X86_OP_IMM:
                                            diff = sop.imm & 0xFFFFFFFF
                                            if 0 < diff <= 0x100:
                                                acc += diff
                                                if acc not in seen and is_valid_ioctl(acc):
                                                    self._register_bruteforce_ioctl(
                                                        acc, ji.address, insns, j, seen)
                                                j += 1
                                                continue
                                            else:
                                                break  # too large, different dispatch
                                    # CMP with small immediate = final IOCTL in chain
                                    # Pattern: cmp eax, N / jne error → ioctl = acc + N
                                    if ji.mnemonic == "cmp" and len(ji.operands) == 2:
                                        cop = ji.operands[1]
                                        if cop.type == x86c.X86_OP_IMM:
                                            cdiff = cop.imm & 0xFFFFFFFF
                                            if 0 < cdiff <= 0x100:
                                                final_code = acc + cdiff
                                                if final_code not in seen and is_valid_ioctl(final_code):
                                                    # Look for JNE (error) or JE (handler)
                                                    self._register_bruteforce_ioctl(
                                                        final_code, ji.address, insns, j, seen)
                                                break  # CMP ends the chain
                                            else:
                                                break
                                    # Stop on control flow breaks
                                    if ji.mnemonic in ("ret", "retn", "int3", "jmp", "call"):
                                        break
                                    j += 1
                i += 1

    def _register_bruteforce_ioctl(self, code: int, addr: int,
                                    insns: list, idx: int, seen: set):
        """Register a single IOCTL code found via brute-force scan.
        Purpose assignment is deferred to _resolve_bruteforce_purposes()."""
        seen.add(code)
        decoded = decode_ioctl(code)
        method = code & 0x3
        sev = Severity.HIGH if method == 3 else Severity.MEDIUM
        if code not in self.ioctl_codes:
            self.ioctl_codes.append(code)

        # Find handler VA from JE/JZ after this instruction
        handler_va = None
        for j in range(idx + 1, min(idx + 5, len(insns))):
            ji = insns[j]
            if ji.mnemonic in ("je", "jz") and ji.operands:
                jop = ji.operands[0]
                if jop.type == x86c.X86_OP_IMM:
                    handler_va = jop.imm
                    break
            # For CMP+JNE pattern (end of chain), look for JNE then the
            # fall-through is the handler
            if ji.mnemonic in ("jne", "jnz") and ji.operands:
                # The code after JNE is the handler for matching case
                if j + 1 < len(insns):
                    handler_va = insns[j + 1].address
                break
            if ji.mnemonic in ("cmp", "sub", "jmp"):
                break
        # Store handler VA for deferred purpose resolution
        if handler_va is not None:
            self._bruteforce_handler_map[code] = handler_va

        det = {"ioctl_code": decoded["code"], "method": decoded["method_name"]}
        if handler_va is not None:
            det["handler"] = f"0x{handler_va:X}"
        self.findings.append(Finding(
            title=f"IOCTL code: {decoded['code']}",
            severity=sev,
            description=f"Method: {decoded['method_name']}, Access: {decoded['access_name']}",
            location=f"0x{addr:X}",
            poc_hint="ioctl_method_neither" if method == 3 else "ioctl_generic",
            ioctl_code=code,
            details=det,
        ))

    def _resolve_bruteforce_purposes(self):
        """Resolve purposes for brute-force-found IOCTLs with handler bounding."""
        if not self._bruteforce_handler_map:
            return
        # Build bounds from all known handler VAs
        handler_vas_sorted = sorted(set(self._bruteforce_handler_map.values()))
        handler_bounds: Dict[int, int] = {}
        for idx, hva in enumerate(handler_vas_sorted):
            if idx + 1 < len(handler_vas_sorted):
                nxt = handler_vas_sorted[idx + 1]
                if 0 < (nxt - hva) < 0x400:
                    handler_bounds[hva] = nxt
        # Now assign purposes with bounding
        for code, handler_va in self._bruteforce_handler_map.items():
            if code not in self.ioctl_purposes:
                ma = handler_bounds.get(handler_va, 0)
                purpose = self._get_ioctl_purpose(handler_va, max_addr=ma)
                if purpose:
                    self.ioctl_purposes[code] = purpose
        self._bruteforce_handler_map.clear()

    def _get_ioctl_purpose(self, handler_va: int,
                           _depth: int = 0,
                           _visited: Optional[set] = None,
                           max_addr: int = 0) -> Optional[str]:
        """
        Walk the call tree from handler_va (depth <= 2).
        Collects purpose labels, prioritizing DIRECT calls (depth 0-1)
        over deeper ones.  Returns the label with the highest
        depth-adjusted priority so that shared helper functions found
        deep in the call tree don't override the handler's own purpose.

        max_addr: if > 0, stop disassembly at this address (bounds handler
        within a switch-case block to prevent bleed into next handler).

        Returns (label, effective_priority) internally, label externally.
        """
        result = self._get_ioctl_purpose_inner(handler_va, _depth, _visited, max_addr)
        return result[0] if result else None

    def _get_ioctl_purpose_inner(self, handler_va: int,
                                  _depth: int = 0,
                                  _visited: Optional[set] = None,
                                  max_addr: int = 0
                                  ) -> Optional[Tuple[str, int]]:
        if _depth > 4:
            return None
        if _visited is None:
            _visited = set()
        if handler_va in _visited:
            return None
        _visited.add(handler_va)

        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        rva = handler_va - image_base
        data = self.pe.get_bytes_at_rva(rva, 4096)
        if not data:
            return None

        best_label: Optional[str] = None
        best_prio: int = -1
        internal_calls: List[int] = []

        # Disassemble the handler, stopping at ret OR unconditional jmp
        # (switch-case handlers end with jmp to epilogue, not ret).
        # Tail-call jmps (short function -> jmp to real impl) are followed.
        insns = []
        for insn in self.dis.cs.disasm(data, handler_va):
            # If we have a max address bound (switch-case), stop there
            if max_addr and insn.address >= max_addr:
                break
            insns.append(insn)
            if len(insns) >= 200:
                break
            if insn.mnemonic in ("ret", "retn", "int3") and len(insns) > 5:
                break
            # Stop at unconditional jmp when it signals end of handler.
            # Early backward jmps (< 30 insns) are typically error-return paths
            # within the handler; late backward jmps signal end of case block.
            if insn.mnemonic == "jmp" and len(insns) > 5 and insn.operands:
                op = insn.operands[0]
                if op.type == x86c.X86_OP_IMM:
                    jmp_target = op.imm
                    # Backward jmp — only stop if we've scanned enough insns
                    # (error-return paths are early; handler-end jmps are late)
                    if jmp_target <= handler_va:
                        if len(insns) > 25:
                            break
                        # Early backward jmp — error path, continue scanning
                        continue
                    # Very far forward -> likely tail-call to another function
                    fwd_dist = jmp_target - handler_va
                    if fwd_dist > 0x800:
                        if len(insns) <= 10:
                            internal_calls.append(jmp_target)
                        break
                    # Moderate forward — continue linear disassembly
                    # (if/else branches, goto epilogue, etc.)
        if len(insns) <= 4:
            # Only expand if no call instructions found yet — short handlers
            # like "call X; jmp merge" already have all we need
            has_call = any(i.mnemonic == "call" for i in insns)
            if not has_call:
                if max_addr:
                    bounded_size = max_addr - handler_va
                    insns = self.dis.disassemble_range(
                        data[:bounded_size], handler_va, max_insns=80)
                else:
                    insns = self.dis.disassemble_range(
                        data, handler_va, max_insns=80)

        # Depth penalty: deeper calls get reduced priority so they don't
        # override direct handler purpose from shared utility functions.
        depth_penalty = _depth * 3

        for insn in insns:
            if insn.mnemonic != "call" or not insn.operands:
                continue
            op = insn.operands[0]
            call_target: Optional[int] = None
            if op.type == x86c.X86_OP_IMM:
                call_target = op.imm
            elif (op.type == x86c.X86_OP_MEM and
                  op.mem.base == x86c.X86_REG_RIP and
                  op.mem.index == 0):
                call_target = insn.address + insn.size + op.mem.disp
            if call_target is None:
                continue
            if call_target in self.pe.iat_map:
                entry = HANDLER_PURPOSE_MAP.get(self.pe.iat_map[call_target])
                if entry:
                    label, prio = entry
                    effective = prio - depth_penalty
                    if effective > best_prio:
                        best_label, best_prio = label, effective
            else:
                internal_calls.append(call_target)

        # Recurse into internal call targets; keep highest-priority result
        for target in internal_calls:
            result = self._get_ioctl_purpose_inner(target, _depth + 1, _visited)
            if result:
                child_label, child_prio = result
                if child_prio > best_prio:
                    best_label, best_prio = child_label, child_prio

        if best_label is not None:
            return (best_label, best_prio)
        return None

    def _get_handler_va(self, code: int) -> Optional[int]:
        """Return handler VA for an IOCTL code, or None."""
        for f in self.findings:
            if f.ioctl_code == code and f.details and "handler" in f.details:
                try:
                    return int(f.details["handler"], 16)
                except (ValueError, TypeError):
                    pass
        return None

    # ── Feature: IOCTL Structure Recovery ─────────────────────────────────

    def scan_ioctl_structures(self):
        """
        Reverse-engineer the input/output buffer struct layout for each IOCTL
        handler by analyzing how fields at [buffer+offset] are accessed.
        Tracks register propagation from SystemBuffer and records field
        accesses with offset, size, access type, and optional constraints.
        """
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        # Register IDs for buffer propagation tracking (x64)
        BUF_LOAD_DISP = 0x18  # [rdx+0x18] = IRP->AssociatedIrp.SystemBuffer

        # Map capstone register IDs to parent 64-bit register IDs for aliasing
        _REG_FAMILIES_64 = {
            x86c.X86_REG_RAX: x86c.X86_REG_RAX, x86c.X86_REG_EAX: x86c.X86_REG_RAX,
            x86c.X86_REG_AX: x86c.X86_REG_RAX, x86c.X86_REG_AL: x86c.X86_REG_RAX,
            x86c.X86_REG_AH: x86c.X86_REG_RAX,
            x86c.X86_REG_RBX: x86c.X86_REG_RBX, x86c.X86_REG_EBX: x86c.X86_REG_RBX,
            x86c.X86_REG_BX: x86c.X86_REG_RBX, x86c.X86_REG_BL: x86c.X86_REG_RBX,
            x86c.X86_REG_BH: x86c.X86_REG_RBX,
            x86c.X86_REG_RCX: x86c.X86_REG_RCX, x86c.X86_REG_ECX: x86c.X86_REG_RCX,
            x86c.X86_REG_CX: x86c.X86_REG_RCX, x86c.X86_REG_CL: x86c.X86_REG_RCX,
            x86c.X86_REG_CH: x86c.X86_REG_RCX,
            x86c.X86_REG_RDX: x86c.X86_REG_RDX, x86c.X86_REG_EDX: x86c.X86_REG_RDX,
            x86c.X86_REG_DX: x86c.X86_REG_RDX, x86c.X86_REG_DL: x86c.X86_REG_RDX,
            x86c.X86_REG_DH: x86c.X86_REG_RDX,
            x86c.X86_REG_RSI: x86c.X86_REG_RSI, x86c.X86_REG_ESI: x86c.X86_REG_RSI,
            x86c.X86_REG_SI: x86c.X86_REG_RSI,
            x86c.X86_REG_RDI: x86c.X86_REG_RDI, x86c.X86_REG_EDI: x86c.X86_REG_RDI,
            x86c.X86_REG_DI: x86c.X86_REG_RDI,
            x86c.X86_REG_R8: x86c.X86_REG_R8, x86c.X86_REG_R8D: x86c.X86_REG_R8,
            x86c.X86_REG_R8W: x86c.X86_REG_R8, x86c.X86_REG_R8B: x86c.X86_REG_R8,
            x86c.X86_REG_R9: x86c.X86_REG_R9, x86c.X86_REG_R9D: x86c.X86_REG_R9,
            x86c.X86_REG_R9W: x86c.X86_REG_R9, x86c.X86_REG_R9B: x86c.X86_REG_R9,
            x86c.X86_REG_R10: x86c.X86_REG_R10, x86c.X86_REG_R10D: x86c.X86_REG_R10,
            x86c.X86_REG_R10W: x86c.X86_REG_R10, x86c.X86_REG_R10B: x86c.X86_REG_R10,
            x86c.X86_REG_R11: x86c.X86_REG_R11, x86c.X86_REG_R11D: x86c.X86_REG_R11,
            x86c.X86_REG_R11W: x86c.X86_REG_R11, x86c.X86_REG_R11B: x86c.X86_REG_R11,
            x86c.X86_REG_R12: x86c.X86_REG_R12, x86c.X86_REG_R12D: x86c.X86_REG_R12,
            x86c.X86_REG_R12W: x86c.X86_REG_R12, x86c.X86_REG_R12B: x86c.X86_REG_R12,
            x86c.X86_REG_R13: x86c.X86_REG_R13, x86c.X86_REG_R13D: x86c.X86_REG_R13,
            x86c.X86_REG_R13W: x86c.X86_REG_R13, x86c.X86_REG_R13B: x86c.X86_REG_R13,
            x86c.X86_REG_R14: x86c.X86_REG_R14, x86c.X86_REG_R14D: x86c.X86_REG_R14,
            x86c.X86_REG_R14W: x86c.X86_REG_R14, x86c.X86_REG_R14B: x86c.X86_REG_R14,
            x86c.X86_REG_R15: x86c.X86_REG_R15, x86c.X86_REG_R15D: x86c.X86_REG_R15,
            x86c.X86_REG_R15W: x86c.X86_REG_R15, x86c.X86_REG_R15B: x86c.X86_REG_R15,
            x86c.X86_REG_RBP: x86c.X86_REG_RBP, x86c.X86_REG_EBP: x86c.X86_REG_RBP,
            x86c.X86_REG_RSP: x86c.X86_REG_RSP, x86c.X86_REG_ESP: x86c.X86_REG_RSP,
        }

        def _canon(reg_id: int) -> int:
            """Return canonical (64-bit parent) register ID."""
            return _REG_FAMILIES_64.get(reg_id, reg_id)

        # ── Pre-scan: discover SystemBuffer register from dispatch prologue ──
        # Many drivers load SystemBuffer once at the top of the dispatch
        # function (e.g. mov rsi, [rdx+0x18]) and all IOCTL handler blocks
        # use that register.  Scan the IRP_MJ_DEVICE_CONTROL handler
        # prologue to find which register holds the buffer.
        dispatch_buf_regs: set = set()
        dispatch_va = None
        # Try 1: from IRP_MJ_DEVICE_CONTROL finding
        for f in self.findings:
            if f.title and "IRP_MJ_DEVICE_CONTROL" in f.title and "handler" in f.title.lower():
                if f.details and "handler" in f.details:
                    dispatch_va = int(f.details["handler"], 16)
                elif f.location and f.location.startswith("0x"):
                    dispatch_va = int(f.location, 16)
                break
        # Try 2: scan backward from the first handler to find the dispatch
        # function entry and the SystemBuffer load instruction.
        if not dispatch_va and self.ioctl_codes:
            first_handler = None
            for c in self.ioctl_codes:
                hva = self._get_handler_va(c)
                if hva:
                    if first_handler is None or hva < first_handler:
                        first_handler = hva
            if first_handler:
                # Disassemble up to 0x200 bytes before the first handler
                scan_size = 0x200
                scan_start = first_handler - scan_size
                scan_rva = scan_start - image_base
                if scan_rva > 0:
                    scan_data = self.pe.get_bytes_at_rva(scan_rva, scan_size)
                    if scan_data:
                        pre_insns = self.dis.disassemble_range(
                            scan_data, scan_start, max_insns=200)
                        irp_r = _canon(x86c.X86_REG_RDX) if self.dis.is_64bit else None
                        pre_irp_regs = {irp_r} if irp_r else set()
                        for pi in pre_insns:
                            if pi.mnemonic in ("mov", "movzx") and len(pi.operands) == 2:
                                pdst, psrc = pi.operands[0], pi.operands[1]
                                # Track IRP register copies
                                if (pdst.type == x86c.X86_OP_REG and
                                        psrc.type == x86c.X86_OP_REG and
                                        _canon(psrc.reg) in pre_irp_regs):
                                    pre_irp_regs.add(_canon(pdst.reg))
                                # Detect: mov reg, [irp+0x18]
                                if (pdst.type == x86c.X86_OP_REG and
                                        psrc.type == x86c.X86_OP_MEM and
                                        psrc.mem.index == 0 and
                                        _canon(psrc.mem.base) in pre_irp_regs and
                                        psrc.mem.disp == BUF_LOAD_DISP):
                                    dispatch_buf_regs.add(_canon(pdst.reg))
                                # Track buffer reg copies
                                if (pdst.type == x86c.X86_OP_REG and
                                        psrc.type == x86c.X86_OP_REG and
                                        _canon(psrc.reg) in dispatch_buf_regs):
                                    dispatch_buf_regs.add(_canon(pdst.reg))

        if dispatch_va:
            d_rva = dispatch_va - image_base
            d_data = self.pe.get_bytes_at_rva(d_rva, 2048)
            if d_data:
                d_insns = self.dis.disassemble_function(d_data, dispatch_va, max_insns=100)
                irp_r = _canon(x86c.X86_REG_RDX) if self.dis.is_64bit else None
                irp_regs = {irp_r} if irp_r else set()
                for d_insn in d_insns:
                    if d_insn.mnemonic in ("mov", "movzx") and len(d_insn.operands) == 2:
                        ddst, dsrc = d_insn.operands[0], d_insn.operands[1]
                        # Track IRP register propagation
                        if (ddst.type == x86c.X86_OP_REG and
                                dsrc.type == x86c.X86_OP_REG and
                                _canon(dsrc.reg) in irp_regs):
                            irp_regs.add(_canon(ddst.reg))
                        # Detect mov reg, [irp+0x18] (SystemBuffer load)
                        if (ddst.type == x86c.X86_OP_REG and
                                dsrc.type == x86c.X86_OP_MEM and
                                dsrc.mem.index == 0 and
                                _canon(dsrc.mem.base) in irp_regs and
                                dsrc.mem.disp == BUF_LOAD_DISP):
                            dispatch_buf_regs.add(_canon(ddst.reg))
                        # Also track register copies of buffer reg
                        if (ddst.type == x86c.X86_OP_REG and
                                dsrc.type == x86c.X86_OP_REG and
                                _canon(dsrc.reg) in dispatch_buf_regs):
                            dispatch_buf_regs.add(_canon(ddst.reg))

        for code in self.ioctl_codes:
            handler_va = self._get_handler_va(code)
            if handler_va is None:
                continue

            rva = handler_va - image_base
            data = self.pe.get_bytes_at_rva(rva, 8192)
            if not data:
                continue

            insns = self.dis.disassemble_function(data, handler_va, max_insns=500)
            if not insns:
                continue

            # Set of canonical register IDs that hold the buffer pointer
            # Seed with registers discovered from dispatch prologue
            buf_regs: set = set(dispatch_buf_regs)
            # Recorded struct fields: (offset, size, access, constraint, reg_name)
            fields: List[dict] = []
            seen_offsets: set = set()  # (offset, size, access) dedup

            # On x64, rdx = IRP on entry to dispatch routine
            irp_reg = _canon(x86c.X86_REG_RDX) if self.dis.is_64bit else None

            for insn in insns:
                ops = insn.operands
                mnem = insn.mnemonic

                # ── Detect SystemBuffer load: mov reg, [irp_reg+0x18] ────
                if mnem in ("mov", "movzx") and len(ops) == 2:
                    dst, src = ops[0], ops[1]
                    if (dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_MEM
                            and src.mem.index == 0):
                        base_canon = _canon(src.mem.base)
                        dst_canon = _canon(dst.reg)
                        # IRP->AssociatedIrp.SystemBuffer at [rdx+0x18]
                        if base_canon == irp_reg and src.mem.disp == BUF_LOAD_DISP:
                            buf_regs.add(dst_canon)
                            continue

                # ── Register propagation: mov reg, buf_reg / lea reg, [buf_reg] ─
                if mnem == "mov" and len(ops) == 2:
                    dst, src = ops[0], ops[1]
                    if dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_REG:
                        src_canon = _canon(src.reg)
                        dst_canon = _canon(dst.reg)
                        if src_canon in buf_regs:
                            buf_regs.add(dst_canon)
                        elif dst_canon in buf_regs and src_canon != dst_canon:
                            # dst is overwritten with non-buffer value
                            buf_regs.discard(dst_canon)

                if mnem == "lea" and len(ops) == 2:
                    dst, src = ops[0], ops[1]
                    if dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_MEM:
                        if src.mem.index == 0 and _canon(src.mem.base) in buf_regs and src.mem.disp == 0:
                            buf_regs.add(_canon(dst.reg))

                # ── Read access: mov reg, [buf_reg+disp] / movzx reg, [buf+disp] ─
                if mnem in ("mov", "movzx", "movsx") and len(ops) == 2:
                    dst, src = ops[0], ops[1]
                    if dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_MEM:
                        if src.mem.index == 0 and _canon(src.mem.base) in buf_regs:
                            offset = src.mem.disp
                            size = src.size
                            key = (offset, size, "read")
                            if key not in seen_offsets:
                                seen_offsets.add(key)
                                fields.append({
                                    "offset": offset,
                                    "size": size,
                                    "access": "read",
                                    "constraint": None,
                                    "reg": insn.reg_name(dst.reg),
                                })

                # ── Write access: mov [buf_reg+disp], reg/imm ─────────────
                if mnem == "mov" and len(ops) == 2:
                    dst, src = ops[0], ops[1]
                    if dst.type == x86c.X86_OP_MEM and dst.mem.index == 0:
                        if _canon(dst.mem.base) in buf_regs:
                            offset = dst.mem.disp
                            size = dst.size
                            src_name = insn.reg_name(src.reg) if src.type == x86c.X86_OP_REG else "imm"
                            key = (offset, size, "write")
                            if key not in seen_offsets:
                                seen_offsets.add(key)
                                fields.append({
                                    "offset": offset,
                                    "size": size,
                                    "access": "write",
                                    "constraint": None,
                                    "reg": src_name,
                                })

                # ── Compare: cmp [buf_reg+disp], imm -> constraint ─────────
                if mnem == "cmp" and len(ops) == 2:
                    lhs, rhs = ops[0], ops[1]
                    if (lhs.type == x86c.X86_OP_MEM and rhs.type == x86c.X86_OP_IMM
                            and lhs.mem.index == 0 and _canon(lhs.mem.base) in buf_regs):
                        offset = lhs.mem.disp
                        size = lhs.size
                        constraint = rhs.imm
                        key = (offset, size, "cmp")
                        if key not in seen_offsets:
                            seen_offsets.add(key)
                            fields.append({
                                "offset": offset,
                                "size": size,
                                "access": "cmp",
                                "constraint": constraint,
                                "reg": "mem",
                            })

                # ── Kill buffer register on overwrite by non-buffer source ─
                if mnem in ("mov", "lea", "xor", "sub", "add") and len(ops) >= 1:
                    dst = ops[0]
                    if dst.type == x86c.X86_OP_REG:
                        dst_canon = _canon(dst.reg)
                        if dst_canon in buf_regs:
                            # xor reg, reg or other clobber
                            if mnem == "xor" and len(ops) == 2 and ops[1].type == x86c.X86_OP_REG:
                                if _canon(ops[1].reg) == dst_canon:
                                    buf_regs.discard(dst_canon)
                            # Already handled mov reg-to-reg above; skip re-kill for those
                            # For lea with non-zero disp from buffer, it's an offset ptr (not buffer base)

            # ── Infer field types from data flow to API calls ────────
            # Track which register holds each buffer field, then scan
            # forward to find which API receives it and in which arg slot.
            field_reg_map: Dict[int, dict] = {}  # canon_reg -> field dict
            for fld in fields:
                if fld["access"] == "read" and fld.get("reg"):
                    reg_name = fld["reg"]
                    # Find the capstone reg id from name
                    for rid, canon in _REG_FAMILIES_64.items():
                        if insns and insns[0].reg_name(rid) == reg_name:
                            field_reg_map[canon] = fld
                            break

            # x64 ABI argument registers in order
            _ARG_REG_CANON = [
                _canon(x86c.X86_REG_RCX), _canon(x86c.X86_REG_RDX),
                _canon(x86c.X86_REG_R8), _canon(x86c.X86_REG_R9),
            ]

            # API parameter -> field type inference
            _API_PARAM_TYPE = {
                # (api_name, arg_index) -> field_type
                ("PsLookupProcessByProcessId", 0): "PID",
                ("PsLookupThreadByThreadId", 0): "TID",
                ("ZwOpenProcess", 0): "PHANDLE",
                ("ZwTerminateProcess", 0): "HANDLE",
                ("ZwTerminateProcess", 1): "NTSTATUS",
                ("ObReferenceObjectByHandle", 0): "HANDLE",
                ("ZwClose", 0): "HANDLE",
                ("ZwOpenProcessToken", 0): "HANDLE",
                ("ZwOpenProcessTokenEx", 0): "HANDLE",
                ("MmMapIoSpace", 0): "PHYSICAL_ADDRESS",
                ("MmMapIoSpaceEx", 0): "PHYSICAL_ADDRESS",
                ("MmMapIoSpace", 1): "SIZE",
                ("MmMapIoSpaceEx", 1): "SIZE",
                ("MmCopyVirtualMemory", 1): "ADDRESS",
                ("MmCopyVirtualMemory", 3): "ADDRESS",
                ("MmCopyVirtualMemory", 4): "SIZE",
                ("ZwReadVirtualMemory", 1): "ADDRESS",
                ("ZwReadVirtualMemory", 2): "BUFFER_PTR",
                ("ZwReadVirtualMemory", 3): "SIZE",
                ("ZwWriteVirtualMemory", 1): "ADDRESS",
                ("ZwWriteVirtualMemory", 2): "BUFFER_PTR",
                ("ZwWriteVirtualMemory", 3): "SIZE",
                ("NtReadVirtualMemory", 1): "ADDRESS",
                ("NtWriteVirtualMemory", 1): "ADDRESS",
                ("ZwMapViewOfSection", 0): "HANDLE",
                ("ZwAllocateVirtualMemory", 0): "HANDLE",
                ("ZwAllocateVirtualMemory", 3): "SIZE",
                ("ExAllocatePoolWithTag", 1): "SIZE",
                ("ExAllocatePool", 1): "SIZE",
                ("ExAllocatePool2", 2): "SIZE",
                ("__writemsr", 0): "MSR_INDEX",
                ("__readmsr", 0): "MSR_INDEX",
                ("_writemsr", 0): "MSR_INDEX",
                ("_readmsr", 0): "MSR_INDEX",
                ("__writecr0", 0): "CR_VALUE",
                ("ZwCreateFile", 0): "PHANDLE",
                ("ZwSetValueKey", 0): "HANDLE",
                ("KeAttachProcess", 0): "PEPROCESS",
                ("KeStackAttachProcess", 0): "PEPROCESS",
                ("__outbyte", 0): "IO_PORT",
                ("__outbyte", 1): "IO_DATA",
                ("__outdword", 0): "IO_PORT",
                ("__outdword", 1): "IO_DATA",
                ("__inbyte", 0): "IO_PORT",
                ("__indword", 0): "IO_PORT",
                ("HalSetBusData", 3): "PCI_OFFSET",
                ("HalSetBusData", 4): "SIZE",
                ("HalGetBusData", 3): "PCI_OFFSET",
                ("HalGetBusData", 4): "SIZE",
            }

            # Scan instructions to link buffer field reads -> API call args
            # Build a map: which register holds which field at each point
            active_field_regs: Dict[int, dict] = {}  # canon_reg -> field
            for idx_i, insn in enumerate(insns):
                ops = insn.operands
                mnem = insn.mnemonic

                # Track buffer field loads into registers
                if mnem in ("mov", "movzx", "movsx") and len(ops) == 2:
                    dst, src = ops[0], ops[1]
                    if (dst.type == x86c.X86_OP_REG and
                            src.type == x86c.X86_OP_MEM and
                            src.mem.index == 0 and
                            _canon(src.mem.base) in buf_regs):
                        offset = src.mem.disp
                        dst_canon = _canon(dst.reg)
                        # Find matching field
                        for fld in fields:
                            if fld["offset"] == offset and fld["access"] == "read":
                                active_field_regs[dst_canon] = fld
                                break

                # Track register-to-register propagation
                if mnem == "mov" and len(ops) == 2:
                    dst, src = ops[0], ops[1]
                    if dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_REG:
                        src_c = _canon(src.reg)
                        dst_c = _canon(dst.reg)
                        if src_c in active_field_regs:
                            active_field_regs[dst_c] = active_field_regs[src_c]
                        elif dst_c in active_field_regs:
                            del active_field_regs[dst_c]

                # At CALL instructions, check if any arg registers hold buffer fields
                if mnem == "call" and ops:
                    op = ops[0]
                    call_target = None
                    if op.type == x86c.X86_OP_IMM:
                        call_target = op.imm
                    elif (op.type == x86c.X86_OP_MEM and
                          op.mem.base == x86c.X86_REG_RIP and
                          op.mem.index == 0):
                        call_target = insn.address + insn.size + op.mem.disp
                    if call_target and call_target in self.pe.iat_map:
                        fn_name = self.pe.iat_map[call_target]
                        for arg_idx, arg_reg in enumerate(_ARG_REG_CANON):
                            if arg_reg in active_field_regs:
                                fld = active_field_regs[arg_reg]
                                type_key = (fn_name, arg_idx)
                                if type_key in _API_PARAM_TYPE:
                                    fld["field_type"] = _API_PARAM_TYPE[type_key]
                                    fld["used_by"] = fn_name
                                elif not fld.get("used_by"):
                                    fld["used_by"] = fn_name
                    # After call, volatile regs are clobbered
                    for vol_r in (_canon(x86c.X86_REG_RAX), _canon(x86c.X86_REG_RCX),
                                  _canon(x86c.X86_REG_RDX), _canon(x86c.X86_REG_R8),
                                  _canon(x86c.X86_REG_R9), _canon(x86c.X86_REG_R10),
                                  _canon(x86c.X86_REG_R11)):
                        active_field_regs.pop(vol_r, None)

            # ── Also infer from IOCTL purpose when no data-flow match ────
            purpose = self.ioctl_purposes.get(code, "")
            _PURPOSE_FIELD_HINTS = {
                "process kill": {0: ("PID", 4), 4: ("FLAGS", 4)},
                "process lookup": {0: ("PID", 4)},
                "process access": {0: ("PID", 4)},
                "process attach": {0: ("PID", 4)},
                "token steal": {0: ("SRC_PID", 4), 4: ("DST_PID", 4)},
                "token modify": {0: ("PID", 4), 4: ("TOKEN_INFO_CLASS", 4)},
                "token access": {0: ("PID", 4)},
                "adjust privileges": {0: ("PID", 4), 4: ("PRIVILEGE_LUID", 4)},
                "phys mem map": {0: ("PHYSICAL_ADDRESS", 8), 8: ("SIZE", 4)},
                "mem copy": {0: ("SRC_PID", 4), 4: ("SRC_ADDR", 8), 12: ("DST_ADDR", 8), 20: ("SIZE", 4)},
                "mem read": {0: ("PID", 4), 4: ("ADDRESS", 8), 12: ("SIZE", 4)},
                "mem write": {0: ("PID", 4), 4: ("ADDRESS", 8), 12: ("SIZE", 4)},
                "alloc memory": {0: ("PID", 4), 4: ("SIZE", 8)},
                "free memory": {0: ("PID", 4), 4: ("ADDRESS", 8)},
                "change protection": {0: ("PID", 4), 4: ("ADDRESS", 8), 12: ("SIZE", 4), 16: ("PROTECT", 4)},
                "create thread": {0: ("PID", 4), 4: ("START_ADDR", 8), 12: ("PARAM", 8)},
                "delete file": {0: ("PATH_PTR", 8)},
                "query system": {0: ("INFO_CLASS", 4), 4: ("BUF_SIZE", 4)},
                "MSR read": {0: ("MSR_INDEX", 4)},
                "MSR write": {0: ("MSR_INDEX", 4), 4: ("MSR_VALUE", 4)},
                "CR0 write": {0: ("CR_VALUE", 8)},
                "CR4 write": {0: ("CR_VALUE", 8)},
                "mem map": {0: ("ADDRESS", 8), 8: ("SIZE", 4)},
                "load driver": {0: ("PATH_PTR", 8)},
                "registry write": {0: ("KEY_PTR", 8), 8: ("VALUE_PTR", 8)},
                "registry delete": {0: ("KEY_PTR", 8)},
                "file write": {0: ("PATH_PTR", 8), 8: ("DATA_PTR", 8), 16: ("SIZE", 4)},
            }
            if purpose in _PURPOSE_FIELD_HINTS:
                hints = _PURPOSE_FIELD_HINTS[purpose]
                for fld in fields:
                    if not fld.get("field_type") and fld["offset"] in hints:
                        hint_type, hint_sz = hints[fld["offset"]]
                        if fld["size"] <= hint_sz:
                            fld["field_type"] = hint_type

            # Sort fields by offset
            fields.sort(key=lambda f: (f["offset"], f["size"]))

            if fields:
                self.ioctl_structs[code] = fields
                decoded = decode_ioctl(code)

                # Build human-readable struct layout
                layout_lines = []
                for fld in fields:
                    c_str = ""
                    if fld["constraint"] is not None:
                        c_str = f"  (constrained: == 0x{fld['constraint']:X})"
                    type_str = ""
                    if fld.get("field_type"):
                        type_str = f"  [{fld['field_type']}]"
                    used_str = ""
                    if fld.get("used_by") and not fld.get("field_type"):
                        used_str = f"  → {fld['used_by']}"
                    layout_lines.append(
                        f"  +0x{fld['offset']:04X}  {fld['size']}B  "
                        f"{fld['access']:5s}  via {fld['reg']}{type_str}{used_str}{c_str}"
                    )

                self.findings.append(Finding(
                    title=f"Recovered IOCTL buffer struct for {decoded['code']}",
                    severity=Severity.INFO,
                    description=(
                        f"Reconstructed input/output buffer layout for IOCTL "
                        f"{decoded['code']} ({decoded['method_name']}) — "
                        f"{len(fields)} field(s) detected:\n" + "\n".join(layout_lines)
                    ),
                    location=f"0x{handler_va:X}",
                    ioctl_code=code,
                    details={
                        "ioctl": decoded["code"],
                        "handler": f"0x{handler_va:X}",
                        "field_count": str(len(fields)),
                        "fields": fields,
                    },
                ))

    def analyze_ioctl_behaviors(self):
        """
        Deep per-IOCTL handler analysis.  For each IOCTL, disassemble the
        handler, follow internal calls (depth 3), and build a complete
        behavior profile:
          - Every kernel API called (categorized)
          - Inline operations (CR writes, MSR, port I/O, memory access patterns)
          - Security checks present in handler
          - Data flow: buffer -> API argument connections
          - IRP completion behavior
          - Risk assessment per handler
        """
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        self.ioctl_behaviors: Dict[int, dict] = {}

        # Fallback: if no per-IOCTL handler VAs, use the IRP_MJ_DEVICE_CONTROL
        # dispatch handler for all IOCTLs
        dispatch_va = None
        codes_without_handler = [c for c in self.ioctl_codes
                                 if self._get_handler_va(c) is None]
        if codes_without_handler:
            for f in self.findings:
                if f.title and "IRP_MJ_DEVICE_CONTROL" in f.title and "handler" in f.title.lower():
                    if f.details and "handler" in f.details:
                        dispatch_va = int(f.details["handler"], 16)
                    elif f.location and f.location.startswith("0x"):
                        dispatch_va = int(f.location, 16)
                    break

        # Cache: if multiple IOCTLs share the same dispatch VA, analyze once
        _behavior_cache: Dict[int, dict] = {}

        # Build handler VA -> max_addr map for bounding case blocks
        all_handler_vas = []
        for code in self.ioctl_codes:
            hva = self._get_handler_va(code)
            if hva is not None:
                all_handler_vas.append(hva)
        all_handler_vas_sorted = sorted(set(all_handler_vas))
        handler_max_addr: Dict[int, int] = {}
        for i, hva in enumerate(all_handler_vas_sorted):
            if i + 1 < len(all_handler_vas_sorted):
                next_hva = all_handler_vas_sorted[i + 1]
                if 0 < (next_hva - hva) < 0x400:
                    handler_max_addr[hva] = next_hva

        for code in self.ioctl_codes:
            handler_va = self._get_handler_va(code)
            if handler_va is None:
                handler_va = dispatch_va
            if handler_va is None:
                continue

            # Reuse cached behavior for same handler VA (shared dispatch)
            if handler_va in _behavior_cache:
                from copy import deepcopy
                behavior = deepcopy(_behavior_cache[handler_va])
                behavior["handler_va"] = handler_va
                self.ioctl_behaviors[code] = behavior
                continue

            behavior = {
                "handler_va": handler_va,
                "api_calls": [],       # list of {name, category, desc, addr}
                "inline_ops": [],      # list of {type, detail, addr}
                "security_checks": [], # list of check descriptions
                "irp_completion": False,
                "completes_status": None,  # STATUS code if detected
                "calls_subroutines": 0,
                "risk_factors": [],
                "summary": "",
            }

            # Collect API calls across handler + internal subroutines
            visited = set()
            api_calls_set = set()
            ma = handler_max_addr.get(handler_va, 0)
            self._collect_handler_behavior(
                handler_va, behavior, visited, api_calls_set, depth=0,
                max_addr=ma)

            # ── User-buffer taint to dangerous API sites ─────────────────
            # Seed: RCX=DeviceObject, RDX=IRP on entry. The IRP's
            # SystemBuffer lives at offset 0x18 (Irp->AssociatedIrp).
            # The easiest defensive seed: treat any value derived from
            # RDX (IRP) via a memory load as tainted. We also seed RCX
            # because some drivers use WDF where RCX is the request.
            # The TaintTracker then propagates through the handler,
            # including into in-driver callees (interprocedural) and
            # through stack-slot stores (memory taint).
            behavior["tainted_calls"] = self._run_handler_taint(handler_va)

            # ── CFG + path-gate analysis ─────────────────────────────────
            # Compute "is the dangerous API gated on every path?" per
            # API, so primitive classification can distinguish
            # LPE-grade (ungated) from admin-only (gated) primitives.
            behavior["ungated_sinks"] = self._compute_ungated_sinks(
                handler_va, behavior)

            # ── Backward slice — provenance of every dangerous arg ───────
            # Tells us whether each arg of (e.g.) ZwTerminateProcess is
            # an immediate, a fixed global, a stack local, an API return
            # value, or a load from the user buffer at a specific offset.
            # Used to validate forward taint and report exact byte-level
            # exploit info.
            behavior["arg_provenance"] = self._compute_arg_provenance(
                handler_va, behavior)

            # ── Constant propagation + bounds-check inference ────────────
            # Walks the handler with constant folding and pairs each
            # cmp/test with the immediately-following conditional branch
            # to infer "the validated path constrains reg op const."
            # Result is used to mark length/size/offset args that are
            # actually bounds-checked vs. those that aren't.
            behavior["bounds_checks"] = self._compute_bounds_checks(
                handler_va)

            # ── Determine security checks ────────────────────────────────
            api_names = {ac["name"] for ac in behavior["api_calls"]}
            if "ProbeForRead" in api_names or "ProbeForWrite" in api_names:
                behavior["security_checks"].append("Buffer probing (ProbeForRead/Write)")
            if "ExGetPreviousMode" in api_names or "KeGetPreviousMode" in api_names:
                behavior["security_checks"].append("Caller mode check (PreviousMode)")
            if api_names & {"SeSinglePrivilegeCheck", "SePrivilegeCheck", "SeAccessCheck"}:
                behavior["security_checks"].append("Privilege/access check")
            if "ObReferenceObjectByHandle" in api_names:
                behavior["security_checks"].append("Object reference by handle (may validate AccessMode)")

            # ── IRP completion ───────────────────────────────────────────
            if api_names & {"IoCompleteRequest", "IofCompleteRequest"}:
                behavior["irp_completion"] = True

            # ── Risk assessment ──────────────────────────────────────────
            dangerous_cats = {"MEMORY", "CPU", "IO", "TOKEN", "DRIVER", "ETW"}
            dangerous_apis = [ac for ac in behavior["api_calls"]
                              if ac["category"] in dangerous_cats]
            if dangerous_apis and not behavior["security_checks"]:
                behavior["risk_factors"].append(
                    "Dangerous operations WITHOUT security checks")
            if any(ac["name"] in ("MmMapIoSpace", "MmMapIoSpaceEx",
                                   "__writemsr", "__writecr0")
                   for ac in behavior["api_calls"]):
                behavior["risk_factors"].append(
                    "Direct hardware/CPU manipulation")
            if any(ac["name"] in ("ZwTerminateProcess", "NtTerminateProcess")
                   and ac.get("depth", 0) <= 2
                   for ac in behavior["api_calls"]):
                behavior["risk_factors"].append("Can terminate arbitrary processes")
            if any(ac["name"] in ("ZwWriteVirtualMemory", "NtWriteVirtualMemory",
                                   "MmCopyVirtualMemory")
                   and ac.get("depth", 0) <= 1
                   for ac in behavior["api_calls"]):
                behavior["risk_factors"].append("Cross-process memory write")

            # ── Token steal detection ───────────────────────────────
            token_apis = {ac["name"] for ac in behavior["api_calls"]
                          if ac["name"] in ("PsInitialSystemProcess",
                                            "PsReferencePrimaryToken",
                                            "PsReferenceImpersonationToken",
                                            "ZwOpenProcessToken", "ZwOpenProcessTokenEx",
                                            "NtOpenProcessToken", "NtOpenProcessTokenEx",
                                            "ZwDuplicateToken", "NtDuplicateToken")}
            has_process_resolve = any(ac["name"] in (
                "PsLookupProcessByProcessId", "ZwOpenProcess", "NtOpenProcess")
                for ac in behavior["api_calls"])
            token_writes = behavior.get("token_offset_writes", [])
            if token_apis and has_process_resolve:
                behavior["risk_factors"].append(
                    f"TOKEN STEAL: references {', '.join(sorted(token_apis))} + process resolve")
            if token_writes and has_process_resolve:
                offsets = ", ".join(tw["offset"] for tw in token_writes[:3])
                behavior["risk_factors"].append(
                    f"TOKEN STEAL: writes EPROCESS token offset ({offsets})")

            # ── PPL bypass detection ────────────────────────────────
            ppl_writes = behavior.get("ppl_byte_writes", [])
            if ppl_writes and has_process_resolve:
                offsets = ", ".join(pw["offset"] for pw in ppl_writes[:3])
                behavior["risk_factors"].append(
                    f"PPL BYPASS: byte write at EPROCESS offset ({offsets}) + process resolve")

            # ── Token modification detection ────────────────────────
            if any(ac["name"] in ("ZwSetInformationToken", "NtSetInformationToken",
                                   "ZwAdjustPrivilegesToken", "NtAdjustPrivilegesToken")
                   for ac in behavior["api_calls"]):
                behavior["risk_factors"].append("Can modify token privileges/information")

            # ── Thread injection detection ──────────────────────────
            if any(ac["name"] in ("RtlCreateUserThread", "ZwCreateThreadEx",
                                   "NtCreateThreadEx")
                   and ac.get("depth", 0) <= 1
                   for ac in behavior["api_calls"]):
                behavior["risk_factors"].append("Can create threads in other processes (injection)")

            # ── Callback removal detection ────────────────────────────
            callback_removal_apis = api_names & {
                "PsRemoveCreateThreadNotifyRoutine",
                "PsRemoveLoadImageNotifyRoutine",
                "CmUnRegisterCallback",
                "ObUnRegisterCallbacks",
            }
            if callback_removal_apis:
                behavior["risk_factors"].append(
                    f"CALLBACK REMOVAL: {', '.join(sorted(callback_removal_apis))}")
            # PsSetCreateProcessNotifyRoutine can also remove (Remove=TRUE)
            if "PsSetCreateProcessNotifyRoutine" in api_names:
                behavior["risk_factors"].append(
                    "CALLBACK CONTROL: PsSetCreateProcessNotifyRoutine (can remove callbacks)")

            # ── ETW disabling detection ───────────────────────────────
            etw_control_apis = api_names & {
                "NtTraceControl", "ZwTraceControl", "EtwUnregister",
            }
            if etw_control_apis:
                behavior["risk_factors"].append(
                    f"ETW DISABLE: {', '.join(sorted(etw_control_apis))}")

            # ── EDR token downgrade detection ─────────────────────────
            has_token_modify_risk = api_names & {
                "ZwSetInformationToken", "NtSetInformationToken",
                "ZwAdjustPrivilegesToken", "NtAdjustPrivilegesToken",
            }
            if has_token_modify_risk and has_process_resolve:
                behavior["risk_factors"].append(
                    f"EDR TOKEN DOWNGRADE: {', '.join(sorted(has_token_modify_risk))} + process resolve")

            # ── DSE disable detection ─────────────────────────────────
            if "MmGetSystemRoutineAddress" in api_names:
                behavior["risk_factors"].append(
                    "RUNTIME RESOLVE: MmGetSystemRoutineAddress (can resolve CI exports for DSE bypass)")

            if not behavior["irp_completion"]:
                behavior["risk_factors"].append(
                    "No IRP completion detected (may leak IRP or cause hang)")

            # ── Build summary ────────────────────────────────────────────
            categories = {}
            for ac in behavior["api_calls"]:
                categories.setdefault(ac["category"], []).append(ac["name"])

            summary_parts = []
            # Order by risk importance
            cat_order = ["CPU", "MEMORY", "IO", "TOKEN", "PROCESS",
                         "OBJECT", "POOL", "FILE", "REGISTRY", "DRIVER",
                         "CALLBACK", "ETW", "VALIDATION", "SYNC", "IRP"]
            for cat in cat_order:
                if cat in categories:
                    apis = categories[cat]
                    unique = sorted(set(apis))
                    summary_parts.append(f"{cat}: {', '.join(unique)}")

            if behavior["inline_ops"]:
                inline_summary = set(op["type"] for op in behavior["inline_ops"])
                summary_parts.append(f"INLINE: {', '.join(sorted(inline_summary))}")

            behavior["summary"] = " | ".join(summary_parts) if summary_parts else "No significant operations detected"

            self.ioctl_behaviors[code] = behavior
            _behavior_cache[handler_va] = behavior

        # ── Derive missing purposes from behavior analysis ──────────────
        # Maps API names to purpose labels, ordered by priority
        _BEHAVIOR_PURPOSE_MAP = {
            # Killers
            "ZwTerminateProcess":      ("process kill",     10),
            "NtTerminateProcess":      ("process kill",     10),
            # Token
            "PsInitialSystemProcess":  ("token steal",      10),
            "PsReferencePrimaryToken": ("token steal",       9),
            "ZwDuplicateToken":        ("token steal",       9),
            "ZwSetInformationToken":   ("token modify",      9),
            "NtSetInformationToken":   ("token modify",      9),
            "ZwAdjustPrivilegesToken": ("adjust privileges", 9),
            "ZwOpenProcessToken":      ("token access",      8),
            "ZwOpenProcessTokenEx":    ("token access",      8),
            # Memory
            "MmCopyVirtualMemory":     ("mem copy",          9),
            "ZwReadVirtualMemory":     ("mem read",          9),
            "NtReadVirtualMemory":     ("mem read",          9),
            "ZwWriteVirtualMemory":    ("mem write",         9),
            "NtWriteVirtualMemory":    ("mem write",         9),
            "MmMapIoSpace":            ("phys mem map",      9),
            "ZwAllocateVirtualMemory": ("alloc memory",      8),
            "ZwFreeVirtualMemory":     ("free memory",       8),
            "ZwProtectVirtualMemory":  ("change protection", 8),
            "ZwMapViewOfSection":      ("mem map",           8),
            "MmMapLockedPagesSpecifyCache": ("map pages",    8),
            # Thread
            "RtlCreateUserThread":     ("create thread",     9),
            "ZwCreateThreadEx":        ("create thread",     9),
            # File
            "ZwDeleteFile":            ("delete file",       8),
            "ZwWriteFile":             ("file write",        7),
            "ZwCreateFile":            ("file op",           6),
            # Registry
            "ZwDeleteKey":             ("registry delete",   8),
            "ZwSetValueKey":           ("registry write",    7),
            "ZwOpenKey":               ("registry access",   5),
            # System query
            "ZwQuerySystemInformation":("query system",      7),
            "ZwQueryInformationProcess":("query process",    6),
            # Process
            "KeAttachProcess":         ("process attach",    4),
            "KeStackAttachProcess":    ("process attach",    4),
            "ZwOpenProcess":           ("process access",    5),
            "PsLookupProcessByProcessId": ("process lookup", 3),
            # Callback removal
            "PsRemoveCreateThreadNotifyRoutine": ("callback removal", 10),
            "PsRemoveLoadImageNotifyRoutine":    ("callback removal", 10),
            "CmUnRegisterCallback":              ("callback removal", 10),
            "ObUnRegisterCallbacks":             ("callback removal", 10),
            # ETW
            "NtTraceControl":           ("etw disable",      10),
            "ZwTraceControl":           ("etw disable",      10),
            "EtwUnregister":            ("etw disable",       9),
            # DSE
            "MmGetSystemRoutineAddress":("runtime resolve",   5),
        }
        # Low-priority purposes that can be overridden by behavior analysis
        _LOW_PRIORITY_PURPOSES = {
            "process lookup", "process access", "process attach",
            "validate addr", "get process", "get module",
        }
        for code, beh in self.ioctl_behaviors.items():
            existing = self.ioctl_purposes.get(code, "")
            has_existing = bool(existing)
            # Skip if existing purpose is already high-priority
            if has_existing and existing not in _LOW_PRIORITY_PURPOSES:
                continue
            best_purpose = None
            best_score = -1
            for ac in beh["api_calls"]:
                entry = _BEHAVIOR_PURPOSE_MAP.get(ac["name"])
                if entry:
                    purpose_label, score = entry
                    # Depth penalty: deeper calls get lower priority
                    adj_score = score - ac.get("depth", 0) * 3
                    if adj_score > best_score:
                        best_score = adj_score
                        best_purpose = purpose_label
            # Also check risk factors for purpose
            for rf in beh.get("risk_factors", []):
                if "TOKEN STEAL" in rf and best_score < 10:
                    best_purpose = "token steal"
                    best_score = 10
                elif "PPL BYPASS" in rf and best_score < 10:
                    best_purpose = "ppl bypass"
                    best_score = 10
                elif "CALLBACK REMOVAL" in rf and best_score < 10:
                    best_purpose = "callback removal"
                    best_score = 10
                elif "ETW DISABLE" in rf and best_score < 10:
                    best_purpose = "etw disable"
                    best_score = 10
                elif "EDR TOKEN DOWNGRADE" in rf and best_score < 10:
                    best_purpose = "edr token downgrade"
                    best_score = 10
            if best_purpose:
                # Only override if new purpose is higher priority than existing
                if not has_existing or best_purpose not in _LOW_PRIORITY_PURPOSES:
                    self.ioctl_purposes[code] = best_purpose

        # ── Last-resort fallback for IOCTLs that are still unlabeled ─────
        # Uses inline ops + broad API categories + handler size. This
        # replaces the previous bare "[!] any-user"-only rendering with
        # at least a structural classification so reviewers aren't left
        # guessing what the handler does.
        for code, beh in self.ioctl_behaviors.items():
            if self.ioctl_purposes.get(code):
                continue
            inline_types = {op.get("type", "") for op in beh.get("inline_ops", [])}
            api_names = {ac["name"] for ac in beh["api_calls"]}
            api_cats = {ac["category"] for ac in beh["api_calls"]}
            if inline_types & {"CR0_write", "CR3_write", "CR4_write"}:
                self.ioctl_purposes[code] = "CR register write"
            elif "MSR_write" in inline_types:
                self.ioctl_purposes[code] = "MSR write"
            elif "MSR_read" in inline_types:
                self.ioctl_purposes[code] = "MSR read"
            elif inline_types & {"PORT_write", "PORT_read"}:
                self.ioctl_purposes[code] = "port I/O"
            elif api_names & {"IofCompleteRequest", "IoCompleteRequest"} and len(api_names) <= 2:
                self.ioctl_purposes[code] = "trivial (completes IRP only)"
            elif "SYNC" in api_cats:
                self.ioctl_purposes[code] = "synchronization"
            elif "FILE" in api_cats:
                self.ioctl_purposes[code] = "file operation"
            elif "REGISTRY" in api_cats:
                self.ioctl_purposes[code] = "registry access"
            elif "OBJECT" in api_cats:
                self.ioctl_purposes[code] = "object access"
            elif not beh["api_calls"] and not beh.get("inline_ops"):
                self.ioctl_purposes[code] = "stub (no observable calls)"
            elif beh.get("api_calls"):
                # Fall back to the most interesting category's tag
                for cat in ("MEMORY", "PROCESS", "TOKEN", "IO", "CPU"):
                    if cat in api_cats:
                        self.ioctl_purposes[code] = f"{cat.lower()} access"
                        break

        # ── Emit findings per IOCTL ──────────────────────────────────────
        for code, beh in sorted(self.ioctl_behaviors.items()):
            decoded = decode_ioctl(code)
            purpose = self.ioctl_purposes.get(code, "")

            if beh["risk_factors"]:
                sev = Severity.HIGH
            elif any(ac["category"] in ("MEMORY", "CPU", "IO", "TOKEN")
                     for ac in beh["api_calls"]):
                sev = Severity.MEDIUM
            else:
                sev = Severity.INFO

            api_desc_lines = []
            for ac in beh["api_calls"]:
                api_desc_lines.append(
                    f"  [{ac['category']}] {ac['name']} — {ac['desc']}")

            checks_str = (", ".join(beh["security_checks"])
                          if beh["security_checks"] else "NONE")

            desc = (f"Handler at 0x{beh['handler_va']:X}\n"
                    f"Security checks: {checks_str}\n"
                    f"API calls ({len(beh['api_calls'])}):\n"
                    + "\n".join(api_desc_lines[:20]))
            if beh["risk_factors"]:
                desc += "\nRisk: " + "; ".join(beh["risk_factors"])

            self.findings.append(Finding(
                title=f"IOCTL {decoded['code']} behavior: {beh['summary'][:80]}",
                severity=sev,
                description=desc,
                location=f"0x{beh['handler_va']:X}",
                ioctl_code=code,
                details={
                    "ioctl": decoded["code"],
                    "purpose": purpose,
                    "handler": f"0x{beh['handler_va']:X}",
                    "api_calls": [ac["name"] for ac in beh["api_calls"]],
                    "categories": list(set(ac["category"] for ac in beh["api_calls"])),
                    "security_checks": beh["security_checks"],
                    "risk_factors": beh["risk_factors"],
                    "irp_completion": str(beh["irp_completion"]),
                    "inline_ops": [op["type"] for op in beh["inline_ops"]],
                },
            ))

    def _compute_bounds_checks(self, handler_va: int) -> list:
        """Run constant propagation over the handler and return the
        list of inferred RegBound constraints (reg op const) on the
        fall-through path of each cmp/test.

        Encoded as plain dicts for downstream consumers. ``op`` is
        one of ``<=  <  >=  >  ==  !=``.
        """
        from drivertool import constprop as _cp
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        rva = handler_va - image_base
        data = self.pe.get_bytes_at_rva(rva, 8192)
        if not data:
            return []
        try:
            insns = self.dis.disassemble_function(
                data, handler_va, max_insns=600)
        except Exception:
            return []
        if not insns:
            return []
        try:
            _, bounds = _cp.propagate(insns)
            constraints = _cp.interpret_bounds(insns, bounds)
        except Exception:
            return []
        return [
            {"addr": f"0x{c.addr:X}", "reg": c.reg,
             "op": c.op, "const": c.const}
            for c in constraints
        ]

    def _compute_arg_provenance(self, handler_va: int,
                                  behavior: dict) -> dict:
        """For each dangerous-API call in the handler (or in any helper
        the handler reaches), run backward slicing on each register
        argument and record where each value comes from.

        Returns {call_va_int: [ArgProvenance0, ArgProvenance1, ...]}.

        Implementation note: the dangerous call may live inside a
        helper function reached from the handler — its address won't
        be in the handler's own disasm. We disassemble a backward
        window of up to ~0x300 bytes ending at the call instruction;
        that captures enough context for the slice in the typical case
        without needing full function-boundary recovery.
        """
        from drivertool.slicing import BackwardSlicer
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        DANGEROUS = {
            "ZwTerminateProcess", "NtTerminateProcess",
            "ZwWriteVirtualMemory", "NtWriteVirtualMemory",
            "MmCopyVirtualMemory", "ZwReadVirtualMemory",
            "NtReadVirtualMemory",
            "MmMapIoSpace", "MmMapLockedPagesSpecifyCache",
            "PsLookupProcessByProcessId",
            "ZwOpenProcess", "NtOpenProcess",
            "PsRemoveCreateThreadNotifyRoutine",
            "PsRemoveLoadImageNotifyRoutine",
            "ZwSetValueKey", "NtSetValueKey",
            "ZwDeleteFile", "ZwDeleteKey",
            "__writemsr", "__writecr0",
        }

        result: Dict[int, list] = {}
        for ac in behavior.get("api_calls", []):
            if ac["name"] not in DANGEROUS:
                continue
            if ac.get("depth", 0) > 2:
                continue
            try:
                call_va = int(ac["addr"], 16)
            except (TypeError, ValueError):
                continue

            # Disassemble a backward window ~0x300 bytes before the
            # call site. We intentionally do NOT clamp to handler_va
            # because the dangerous call commonly lives in a helper
            # function at a lower VA than the handler itself.
            window_lo = call_va - 0x300
            # Clamp to the image start so we never dip below the PE.
            min_va = image_base
            if window_lo < min_va:
                window_lo = min_va
            window_size = (call_va - window_lo) + 0x40
            if window_size <= 0 or window_size > 0x4000:
                continue
            wrva = window_lo - image_base
            wdata = self.pe.get_bytes_at_rva(wrva, window_size)
            if not wdata:
                continue
            try:
                insns = self.dis.disassemble_range(
                    wdata, window_lo, max_insns=300)
            except Exception:
                continue
            if not insns:
                continue
            # Find the call index within the window
            call_idx = None
            for i, ins in enumerate(insns):
                if ins.address == call_va:
                    call_idx = i
                    break
            if call_idx is None:
                continue
            try:
                slicer = BackwardSlicer(insns, self.pe.iat_map)
                provs = slicer.classify_call_args(call_idx, arg_count=4)
            except Exception:
                continue
            result[call_va] = [
                {"kind": p.kind, "detail": p.detail,
                 "imm": p.imm_value, "mem_disp": p.mem_disp,
                 "api": p.api_name}
                for p in provs
            ]
        return result

    def _compute_ungated_sinks(self, handler_va: int, behavior: dict) -> dict:
        """For each dangerous-API call site in the handler, use the
        CFG to answer *"does every path from entry to this call go
        through a security gate?"*

        Gates: SeAccessCheck / SePrivilegeCheck / ProbeForRead|Write /
        ExGetPreviousMode / ObReferenceObjectByHandle.

        Returns {call_va_int: ``"gated"`` or ``"ungated"``}. Used by
        primitive classification to split LPE-grade from admin-only.
        """
        from drivertool import cfg as _cfg
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        rva = handler_va - image_base
        data = self.pe.get_bytes_at_rva(rva, 8192)
        if not data:
            return {}
        try:
            insns = self.dis.disassemble_function(data, handler_va,
                                                    max_insns=600)
            graph = _cfg.build_cfg(insns, self.pe.iat_map,
                                    entry_va=handler_va)
        except Exception:
            return {}

        DANGEROUS = {
            "ZwTerminateProcess", "NtTerminateProcess",
            "ZwWriteVirtualMemory", "NtWriteVirtualMemory",
            "MmCopyVirtualMemory", "ZwReadVirtualMemory",
            "NtReadVirtualMemory",
            "MmMapIoSpace", "MmMapLockedPagesSpecifyCache",
            "PsRemoveCreateThreadNotifyRoutine",
            "PsRemoveLoadImageNotifyRoutine",
            "CmUnRegisterCallback", "ObUnRegisterCallbacks",
            "NtTraceControl", "ZwTraceControl", "EtwUnregister",
        }
        result: Dict[int, str] = {}
        for ac in behavior.get("api_calls", []):
            if ac["name"] not in DANGEROUS:
                continue
            if ac.get("depth", 0) > 1:
                continue
            try:
                call_va = int(ac["addr"], 16)
            except (TypeError, ValueError):
                continue
            gated = graph.every_path_passes_through(
                call_va, _cfg.GATE_APIS)
            result[call_va] = "gated" if gated else "ungated"
        return result

    def _run_handler_taint(self, handler_va: int) -> List[dict]:
        """Propagate taint from the IRP input buffer through the handler
        and return every IAT call site that receives a tainted arg.

        Uses summary-augmented interprocedural taint. For any in-driver
        callee, we look up (or lazily compute) its summary in
        ``self._taint_summary_cache``, shared across all handlers in
        the driver. A driver where 30 IOCTLs all funnel through one
        kill helper now analyzes that helper *once*, not 30 times.

        Memory-slot taint propagates through stack saves and pointer
        derefs of tainted base registers (see TaintTracker docs).
        """
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        rva = handler_va - image_base
        data = self.pe.get_bytes_at_rva(rva, 8192)
        if not data:
            return []
        insns = self.dis.disassemble_function(data, handler_va, max_insns=600)
        if not insns:
            return []

        # Resolver used for interprocedural taint: returns the disasm
        # of a callee. Memoized per driver so we don't re-disassemble.
        def _resolve_callee(call_va: int):
            try:
                cached = self._callee_disasm_cache.get(call_va)
                if cached is not None:
                    return cached
                crva = call_va - image_base
                cdata = self.pe.get_bytes_at_rva(crva, 8192)
                if not cdata:
                    self._callee_disasm_cache[call_va] = []
                    return None
                ins = self.dis.disassemble_function(
                    cdata, call_va, max_insns=400)
                self._callee_disasm_cache[call_va] = ins or []
                return ins
            except Exception:
                return None

        try:
            tt = TaintTracker(self.pe.iat_map,
                              resolve_internal_call=_resolve_callee,
                              max_call_depth=2)
            # Share the caller's per-instance summary cache so callee
            # results are reused across handlers in this driver.
            tt._summary_cache = self._taint_summary_cache
            seed = {x86c.X86_REG_RDX, x86c.X86_REG_RCX}
            return tt.analyze(insns, seed)
        except Exception:
            return []

    def _collect_handler_behavior(self, va: int, behavior: dict,
                                   visited: set, api_calls_set: set,
                                   depth: int = 0, max_addr: int = 0):
        """Recursively collect API calls and inline ops from handler code.
        Tracks depth at which each API is found for risk assessment.
        max_addr: if > 0 and depth == 0, stop disassembly at this address."""
        if depth > 3 or va in visited:
            return
        visited.add(va)

        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        rva = va - image_base
        data = self.pe.get_bytes_at_rva(rva, 8192)
        if not data:
            return

        if max_addr and depth == 0:
            # Bound to case block size
            bound_size = max_addr - va
            insns = self.dis.disassemble_range(data[:bound_size], va, max_insns=500)
        else:
            insns = self.dis.disassemble_function(data, va, max_insns=500)
        internal_targets = []

        for insn in insns:
            # ── Detect API calls ─────────────────────────────────────
            if insn.mnemonic == "call" and insn.operands:
                op = insn.operands[0]
                target = None
                if op.type == x86c.X86_OP_IMM:
                    target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    target = insn.address + insn.size + op.mem.disp
                if target is None:
                    continue

                fn = self.pe.iat_map.get(target, "")
                if fn and fn in self._API_BEHAVIOR:
                    key = (fn, insn.address)
                    if key not in api_calls_set:
                        api_calls_set.add(key)
                        cat, desc = self._API_BEHAVIOR[fn]
                        behavior["api_calls"].append({
                            "name": fn,
                            "category": cat,
                            "desc": desc,
                            "addr": f"0x{insn.address:X}",
                            "depth": depth,
                        })
                elif fn and fn not in self._API_BEHAVIOR:
                    # Unknown import — still track it
                    key = (fn, insn.address)
                    if key not in api_calls_set:
                        api_calls_set.add(key)
                        behavior["api_calls"].append({
                            "name": fn,
                            "category": "OTHER",
                            "desc": f"Imported function: {fn}",
                            "addr": f"0x{insn.address:X}",
                            "depth": depth,
                        })
                elif not fn and target not in self.pe.iat_map:
                    # Internal subroutine call
                    internal_targets.append(target)
                    behavior["calls_subroutines"] += 1
                continue

            # ── Detect data imports (lea/mov from IAT — e.g. PsInitialSystemProcess) ──
            if insn.mnemonic in ("lea", "mov") and len(insn.operands) == 2:
                src_op = insn.operands[1]
                if (src_op.type == x86c.X86_OP_MEM and
                        src_op.mem.base == x86c.X86_REG_RIP and
                        src_op.mem.index == 0):
                    ref_addr = insn.address + insn.size + src_op.mem.disp
                    data_fn = self.pe.iat_map.get(ref_addr, "")
                    if data_fn and data_fn in self._API_BEHAVIOR:
                        key = (data_fn, insn.address)
                        if key not in api_calls_set:
                            api_calls_set.add(key)
                            cat, desc = self._API_BEHAVIOR[data_fn]
                            behavior["api_calls"].append({
                                "name": data_fn,
                                "category": cat,
                                "desc": desc,
                                "addr": f"0x{insn.address:X}",
                                "depth": depth,
                            })

            # ── Detect EPROCESS field writes (semantic classifier) ────
            # Previously we had two range-buckets (0x400-0xA00 byte =
            # "PPL", 0x358-0x500 qword = "token"). That's fuzzy — one
            # offset sometimes means TWO different things across builds
            # (e.g. 0x4b8 = Token on Win10 but SignatureLevel on Win8.1).
            # Use eprocess_offsets.classify_eprocess_write() which
            # returns the field name AND primitive tag per offset+size.
            if insn.mnemonic == "mov" and len(insn.operands) == 2:
                dst_op = insn.operands[0]
                if dst_op.type == x86c.X86_OP_MEM:
                    from drivertool.eprocess_offsets import (
                        classify_eprocess_write,
                    )
                    classified = classify_eprocess_write(
                        dst_op.mem.disp, dst_op.size)
                    if classified:
                        field_name, prim_tag = classified
                        entry = {
                            "addr":       f"0x{insn.address:X}",
                            "offset":     f"0x{dst_op.mem.disp:X}",
                            "size":       dst_op.size,
                            "field":      field_name,
                            "primitive":  prim_tag,
                            "depth":      depth,
                        }
                        behavior.setdefault(
                            "eprocess_writes", []).append(entry)
                        # Back-compat buckets — keep populating the old
                        # lists so primitive-classification code that
                        # still reads ppl_byte_writes / token_offset_writes
                        # continues to work without a change wave.
                        if prim_tag == "PPL_BYPASS":
                            behavior.setdefault(
                                "ppl_byte_writes", []).append(entry)
                        elif prim_tag == "TOKEN_STEAL":
                            behavior.setdefault(
                                "token_offset_writes", []).append(entry)

            # ── Detect inline CPU operations ─────────────────────────
            if len(insn.operands) >= 1:
                # CR register writes
                if insn.mnemonic == "mov" and len(insn.operands) == 2:
                    dst = insn.operands[0]
                    if dst.type == x86c.X86_OP_REG:
                        if dst.reg in (x86c.X86_REG_CR0, x86c.X86_REG_CR3, x86c.X86_REG_CR4):
                            reg_name = {x86c.X86_REG_CR0: "CR0",
                                        x86c.X86_REG_CR3: "CR3",
                                        x86c.X86_REG_CR4: "CR4"}.get(dst.reg, "CR?")
                            behavior["inline_ops"].append({
                                "type": f"{reg_name}_write",
                                "detail": f"Direct {reg_name} write (disable protections)",
                                "addr": f"0x{insn.address:X}",
                            })
                    # Reading from CR
                    src = insn.operands[1]
                    if src.type == x86c.X86_OP_REG:
                        if src.reg in (x86c.X86_REG_CR0, x86c.X86_REG_CR3, x86c.X86_REG_CR4):
                            reg_name = {x86c.X86_REG_CR0: "CR0",
                                        x86c.X86_REG_CR3: "CR3",
                                        x86c.X86_REG_CR4: "CR4"}.get(src.reg, "CR?")
                            behavior["inline_ops"].append({
                                "type": f"{reg_name}_read",
                                "detail": f"Direct {reg_name} read",
                                "addr": f"0x{insn.address:X}",
                            })

                # WRMSR / RDMSR
                if insn.mnemonic == "wrmsr":
                    behavior["inline_ops"].append({
                        "type": "MSR_write",
                        "detail": "WRMSR instruction — write Model Specific Register",
                        "addr": f"0x{insn.address:X}",
                    })
                elif insn.mnemonic == "rdmsr":
                    behavior["inline_ops"].append({
                        "type": "MSR_read",
                        "detail": "RDMSR instruction — read Model Specific Register",
                        "addr": f"0x{insn.address:X}",
                    })

                # IN / OUT port instructions
                if insn.mnemonic in ("in", "insd", "insb", "insw"):
                    behavior["inline_ops"].append({
                        "type": "PORT_read",
                        "detail": f"{insn.mnemonic.upper()} — read from I/O port",
                        "addr": f"0x{insn.address:X}",
                    })
                elif insn.mnemonic in ("out", "outsd", "outsb", "outsw"):
                    behavior["inline_ops"].append({
                        "type": "PORT_write",
                        "detail": f"{insn.mnemonic.upper()} — write to I/O port",
                        "addr": f"0x{insn.address:X}",
                    })

                # CLI / STI
                if insn.mnemonic == "cli":
                    behavior["inline_ops"].append({
                        "type": "INT_disable",
                        "detail": "CLI — disable interrupts",
                        "addr": f"0x{insn.address:X}",
                    })
                elif insn.mnemonic == "sti":
                    behavior["inline_ops"].append({
                        "type": "INT_enable",
                        "detail": "STI — enable interrupts",
                        "addr": f"0x{insn.address:X}",
                    })

            # ── Detect STATUS codes being set ────────────────────────
            if insn.mnemonic == "mov" and len(insn.operands) == 2:
                src = insn.operands[1]
                if src.type == x86c.X86_OP_IMM:
                    val = src.imm & 0xFFFFFFFF
                    if val == 0xC0000022:
                        behavior["security_checks"].append(
                            "Returns STATUS_ACCESS_DENIED on failure")
                    elif val == 0xC000000D:
                        behavior["security_checks"].append(
                            "Returns STATUS_INVALID_PARAMETER")

        # Recurse into internal subroutines
        for target in internal_targets:
            self._collect_handler_behavior(
                target, behavior, visited, api_calls_set, depth + 1)

    # ── Bug-class taxonomy ─────────────────────────────────────────────
    # Labels are orthogonal to "purpose"/capability tags. A handler can
    # carry several. Each label maps to how a bug-bar writeup would
    # categorise the primitive — what a red teamer puts in the report.
    BUG_CLASS_DESCRIPTIONS = {
        "missing-probe":
            "METHOD_NEITHER handler dereferences user pointer without "
            "ProbeForRead/Write (kernel-mode write to arbitrary address).",
        "arbitrary-rw":
            "Handler exposes a generic kernel read/write primitive "
            "(MmMapIoSpace, cross-process VM, CR/MSR/port access).",
        "process-kill":
            "Handler resolves PID to PEPROCESS and terminates it "
            "(arbitrary-process-kill primitive).",
        "token-theft":
            "Handler swaps the caller's primary token for another "
            "(typically PsInitialSystemProcess) — local privilege escalation.",
        "callback-tamper":
            "Handler can remove/replace kernel notification callbacks "
            "(CmRegisterCallback, ObRegisterCallbacks, Ps*Notify*) — "
            "blinds EDR.",
        "etw-tamper":
            "Handler can disable/unregister ETW providers — blinds Threat "
            "Intelligence and Microsoft-Windows-Threat-Intelligence sinks.",
        "dse-bypass":
            "Handler resolves an unexported address (MmGetSystemRoutineAddress) "
            "AND writes CR0 — classic g_CiOptions / DSE patch.",
        "toctou-attach":
            "Handler attaches to a caller-supplied PID's address space "
            "without an SeAccessCheck/PreviousMode gate — PID race.",
        "double-fetch":
            "Two reads of the same user-buffer offset with a check in "
            "between (TOCTOU on the input itself).",
        "int-overflow-alloc":
            "Arithmetic on tainted size feeds ExAllocatePool with no "
            "overflow guard — heap corruption on overflow.",
        "length-bounded":
            "Length/size argument has been observed under a const-bounded "
            "comparison (e.g. cmp eax, 0x100; ja) on the validated path — "
            "downgraded severity for any size-based bug class.",
        "length-unbounded":
            "Length/size argument flows from user input to a sensitive "
            "sink (alloc / memcpy) without any const-bounded comparison "
            "in the handler — true unbounded primitive.",
    }

    def classify_ioctl_bugs(self):
        """Tag every IOCTL handler with bug-class labels orthogonal to
        the capability/purpose tags. Reads from self.ioctl_behaviors and
        cross-references self.findings produced earlier in the pipeline.

        Output: self.ioctl_bug_classes: Dict[int, List[str]].
        """
        from typing import Dict as _D, List as _L
        self.ioctl_bug_classes: _D[int, _L[str]] = {}
        if not self.ioctl_behaviors:
            return

        # Cross-reference earlier findings by location → handler range
        overflow_addrs = set()
        doublefetch_addrs = set()
        for f in self.findings:
            if not f.location or not f.location.startswith("0x"):
                continue
            try:
                addr = int(f.location, 16)
            except ValueError:
                continue
            t = f.title or ""
            if "Integer overflow" in t:
                overflow_addrs.add(addr)
            elif "Double-fetch" in t:
                doublefetch_addrs.add(addr)

        # Bound each handler's address range by the next handler's VA
        sorted_hvas = sorted({b["handler_va"]
                              for b in self.ioctl_behaviors.values()})
        handler_end: Dict[int, int] = {}
        for i, hva in enumerate(sorted_hvas):
            nxt = sorted_hvas[i + 1] if i + 1 < len(sorted_hvas) else None
            if nxt is not None and 0 < (nxt - hva) < 0x800:
                handler_end[hva] = nxt
            else:
                handler_end[hva] = hva + 0x800

        for code, beh in self.ioctl_behaviors.items():
            classes: list = []
            api_names = {ac["name"] for ac in beh.get("api_calls", [])}
            inline_types = {op["type"] for op in beh.get("inline_ops", [])}
            sec_checks = beh.get("security_checks", [])
            risk_blob = " | ".join(beh.get("risk_factors", []))
            method = code & 0x3
            has_proc_resolve = bool(api_names & {
                "PsLookupProcessByProcessId", "ZwOpenProcess", "NtOpenProcess",
            })
            has_probe = any("Buffer probing" in s for s in sec_checks)
            has_access_check = any("Privilege/access check" in s
                                   or "Caller mode check" in s
                                   for s in sec_checks)

            # 1. METHOD_NEITHER without probing (kernel-mode pointer deref)
            if method == 3 and not has_probe:
                classes.append("missing-probe")

            # 2. Arbitrary R/W — either via MM/VM APIs or via raw inline ops
            arb_rw = False
            if api_names & {"MmMapIoSpace", "MmMapIoSpaceEx",
                            "MmMapLockedPagesSpecifyCache",
                            "ZwMapViewOfSection"}:
                arb_rw = True
            if inline_types & {"CR0_write", "CR3_write", "CR4_write",
                               "MSR_write", "PORT_write"}:
                arb_rw = True
            if has_proc_resolve and api_names & {
                    "MmCopyVirtualMemory", "ZwWriteVirtualMemory",
                    "NtWriteVirtualMemory", "ZwReadVirtualMemory",
                    "NtReadVirtualMemory"}:
                arb_rw = True
            if arb_rw:
                classes.append("arbitrary-rw")

            # 3. Process-kill primitive (PID → terminate)
            if (api_names & {"ZwTerminateProcess", "NtTerminateProcess"}
                    and has_proc_resolve):
                classes.append("process-kill")

            # 4. Token theft (already detected in risk_factors)
            if "TOKEN STEAL" in risk_blob:
                classes.append("token-theft")

            # 5/6. Callback / ETW tampering
            if "CALLBACK REMOVAL" in risk_blob or "CALLBACK CONTROL" in risk_blob:
                classes.append("callback-tamper")
            if "ETW DISABLE" in risk_blob:
                classes.append("etw-tamper")

            # 7. DSE bypass: runtime resolve + CR0 write in same handler
            if ("MmGetSystemRoutineAddress" in api_names
                    and "CR0_write" in inline_types):
                classes.append("dse-bypass")

            # 8. TOCTOU on attached process — attach + PID resolve, no gate
            if (api_names & {"KeStackAttachProcess", "KeAttachProcess"}
                    and has_proc_resolve and not has_access_check):
                classes.append("toctou-attach")

            # 9/10. Cross-reference findings inside the handler range
            hva = beh["handler_va"]
            end = handler_end.get(hva, hva + 0x800)
            if any(hva <= a < end for a in overflow_addrs):
                classes.append("int-overflow-alloc")
            if any(hva <= a < end for a in doublefetch_addrs):
                classes.append("double-fetch")

            # 11. Length-bound classification.
            # ONLY meaningful when the handler reaches a length-taking
            # sink (allocator / memcpy). Without a sink, "any cmp vs
            # const" fires on every handler that has a switch-case
            # dispatch against the IOCTL code, which is uninteresting
            # noise — so we gate on sink presence first.
            length_sink_apis = {"ExAllocatePool", "ExAllocatePoolWithTag",
                                 "ExAllocatePoolZero", "ExAllocatePool2",
                                 "ExAllocatePool3", "ExAllocatePoolWithQuotaTag",
                                 "RtlCopyMemory", "memcpy", "RtlMoveMemory",
                                 "MmCopyVirtualMemory"}
            has_length_sink = bool({ac["name"] for ac in beh["api_calls"]
                                    if ac.get("depth", 0) <= 1}
                                   & length_sink_apis)
            if has_length_sink:
                bounds = beh.get("bounds_checks") or []
                # Reasonable-sized const upper-bound (rules out the
                # huge sentinel constants used for IOCTL code matching).
                const_upper = [b for b in bounds
                               if b.get("op") in ("<", "<=") and
                                  0 < (b.get("const") or 0) <= 0x100_000]
                if const_upper:
                    classes.append("length-bounded")
                    # Drop int-overflow-alloc when there's an explicit
                    # bound — the constraint prevents the overflow.
                    if "int-overflow-alloc" in classes:
                        classes = [c for c in classes
                                   if c != "int-overflow-alloc"]
                else:
                    classes.append("length-unbounded")

            if classes:
                # Stable order, dedup
                seen = set()
                ordered = [c for c in classes
                           if not (c in seen or seen.add(c))]
                self.ioctl_bug_classes[code] = ordered
