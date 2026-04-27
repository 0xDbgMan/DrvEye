"""EDR/security bypass scanning — callbacks, ETW, DSE."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict

import capstone.x86_const as x86c

from drivertool.constants import Severity
from drivertool.ioctl import decode_ioctl
from drivertool.models import Finding

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class EDRScanMixin:
    """Mixin for EDR/security bypass scans."""

    def scan_callback_removal(self):
        """Detect kernel callback removal patterns — used to blind EDR/AV.
        Drivers that enumerate and remove PsSetCreateProcessNotifyRoutine,
        ObRegisterCallbacks, etc. callbacks can silently disable security products."""
        REMOVAL_APIS = {
            "PsRemoveCreateThreadNotifyRoutine": "Thread-create callback removal",
            "PsRemoveLoadImageNotifyRoutine":    "Image-load callback removal",
            "CmUnRegisterCallback":              "Registry callback removal",
            "ObUnRegisterCallbacks":             "Object-manager callback removal",
        }
        # PsSetCreateProcessNotifyRoutine with Remove=TRUE is also removal
        REGISTER_APIS = {
            "PsSetCreateProcessNotifyRoutine":   "Process-create callback (un)register",
            "PsSetCreateProcessNotifyRoutineEx":  "Process-create callback (un)register (Ex)",
        }
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]

        # Per-IOCTL detection via behavior analysis
        if self.ioctl_behaviors:
            for code, beh in self.ioctl_behaviors.items():
                api_names = {ac["name"] for ac in beh["api_calls"]}
                removal_apis = api_names & set(REMOVAL_APIS.keys())
                register_apis = api_names & set(REGISTER_APIS.keys())
                # PsSetCreateProcessNotifyRoutine can be used for removal (Remove=TRUE)
                if removal_apis or register_apis:
                    decoded = decode_ioctl(code)
                    apis_str = ", ".join(sorted(removal_apis | register_apis))
                    self.findings.append(Finding(
                        title=f"Kernel callback removal via IOCTL {decoded['code']}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IOCTL {decoded['code']} handler calls {apis_str}. "
                            f"This can remove kernel notification callbacks registered by "
                            f"EDR/AV products, blinding them to process creation, image "
                            f"loads, registry operations, and object access. Classic "
                            f"technique to disable security monitoring."
                        ),
                        location=f"0x{beh['handler_va']:X}",
                        poc_hint="callback_removal",
                        ioctl_code=code,
                        details={"removal_apis": apis_str},
                    ))
            return

        # Fallback: global import-based detection
        removal_found = [f for f in all_imports if f in REMOVAL_APIS]
        register_found = [f for f in all_imports if f in REGISTER_APIS]
        if removal_found:
            first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
            self.findings.append(Finding(
                title=f"Kernel callback removal imports: {', '.join(removal_found)}",
                severity=Severity.CRITICAL,
                description=(
                    f"Driver imports callback removal APIs ({', '.join(removal_found)}). "
                    f"These remove EDR/AV kernel callbacks — effectively blinding "
                    f"security products to system events."
                ),
                location="Import Table",
                poc_hint="callback_removal",
                ioctl_code=first_ioctl,
            ))
        # PsSetCreateProcessNotifyRoutine can remove callbacks too
        if "PsSetCreateProcessNotifyRoutine" in all_imports and not removal_found:
            first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
            self.findings.append(Finding(
                title="PsSetCreateProcessNotifyRoutine — potential callback removal",
                severity=Severity.HIGH,
                description=(
                    "Driver imports PsSetCreateProcessNotifyRoutine. When called with "
                    "Remove=TRUE, this unregisters the process creation callback. "
                    "If IOCTL-controlled, can remove EDR process monitoring."
                ),
                location="Import Table",
                poc_hint="callback_removal",
                ioctl_code=first_ioctl,
            ))

    def scan_etw_disable(self):
        """Detect ETW provider disabling patterns — used to blind EDR telemetry.
        EDRs rely on ETW (EtwTi, Microsoft-Windows-Threat-Intelligence) for
        kernel-level telemetry. Patching ETW provider GUIDs, EtwEventWrite, or
        using NtTraceControl to stop sessions disables this visibility."""
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]

        # Per-IOCTL detection via behavior analysis
        if self.ioctl_behaviors:
            for code, beh in self.ioctl_behaviors.items():
                api_names = {ac["name"] for ac in beh["api_calls"]}
                etw_apis = api_names & {
                    "NtTraceControl", "ZwTraceControl",
                    "EtwUnregister",
                }
                has_etw_write_ref = api_names & {"EtwEventWrite", "EtwEventEnabled"}
                # If handler touches ETW control APIs, flag it
                if etw_apis:
                    decoded = decode_ioctl(code)
                    self.findings.append(Finding(
                        title=f"ETW provider disabling via IOCTL {decoded['code']}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IOCTL {decoded['code']} handler calls {', '.join(sorted(etw_apis))}. "
                            f"This can disable ETW trace providers including "
                            f"Microsoft-Windows-Threat-Intelligence (EtwTi), which EDR "
                            f"products depend on for kernel telemetry. Disabling ETW "
                            f"blinds security products to syscall monitoring, memory "
                            f"allocation tracking, and other kernel events."
                        ),
                        location=f"0x{beh['handler_va']:X}",
                        poc_hint="etw_disable",
                        ioctl_code=code,
                    ))
                # Also detect patterns where handler patches EtwEventWrite
                # (inline patching of the function to ret early)
                inline_ops = beh.get("inline_ops", [])
                for op in inline_ops:
                    if op.get("type") in ("MOV_MEM", "WRITE_MEM") and has_etw_write_ref:
                        decoded = decode_ioctl(code)
                        self.findings.append(Finding(
                            title=f"ETW inline patching via IOCTL {decoded['code']}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"IOCTL {decoded['code']} handler references ETW functions "
                                f"and performs memory writes. This suggests inline patching "
                                f"of EtwEventWrite or EtwTi provider enable flags to "
                                f"suppress ETW telemetry at the kernel level."
                            ),
                            location=f"0x{beh['handler_va']:X}",
                            poc_hint="etw_disable",
                            ioctl_code=code,
                        ))
                        break
            return

        # Fallback: import-based detection
        etw_control = [f for f in all_imports
                       if f in ("NtTraceControl", "ZwTraceControl", "EtwUnregister")]
        if etw_control:
            first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
            self.findings.append(Finding(
                title=f"ETW control imports: {', '.join(etw_control)}",
                severity=Severity.HIGH,
                description=(
                    f"Driver imports ETW control APIs ({', '.join(etw_control)}). "
                    f"These can disable ETW trace providers that EDR products rely on "
                    f"for kernel telemetry."
                ),
                location="Import Table",
                poc_hint="etw_disable",
                ioctl_code=first_ioctl,
            ))

        # Check for MmGetSystemRoutineAddress + ETW string patterns (runtime resolve)
        if "MmGetSystemRoutineAddress" in all_imports:
            # Scan data sections for ETW-related unicode strings
            etw_strings = []
            for sec in self.pe.pe.sections:
                sec_data = sec.get_data()
                for pattern in (b"E\x00t\x00w\x00E\x00v\x00e\x00n\x00t\x00W\x00r\x00i\x00t\x00e",
                                b"E\x00t\x00w\x00T\x00i",
                                b"N\x00t\x00T\x00r\x00a\x00c\x00e\x00C\x00o\x00n\x00t\x00r\x00o\x00l"):
                    if pattern in sec_data:
                        etw_strings.append(pattern.decode("utf-16-le", errors="ignore"))
            if etw_strings:
                first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
                self.findings.append(Finding(
                    title=f"Runtime ETW API resolution: {', '.join(etw_strings)}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Driver uses MmGetSystemRoutineAddress to resolve ETW APIs "
                        f"at runtime ({', '.join(etw_strings)}). This avoids import "
                        f"table detection while enabling ETW provider manipulation."
                    ),
                    location="Data Sections + Import Table",
                    poc_hint="etw_disable",
                    ioctl_code=first_ioctl,
                ))

    def scan_callback_bodies(self):
        """
        When the driver registers kernel callbacks (PsSetLoadImageNotifyRoutine,
        PsSetCreateProcessNotifyRoutine, etc.), resolve the callback function
        pointer and analyze what the callback does.
        """
        CALLBACK_APIS = {
            "PsSetLoadImageNotifyRoutine":       "Image-load callback",
            "PsSetCreateProcessNotifyRoutine":   "Process-create callback",
            "PsSetCreateProcessNotifyRoutineEx": "Process-create callback (Ex)",
            "PsSetCreateThreadNotifyRoutine":    "Thread-create callback",
            "CmRegisterCallback":                "Registry callback",
            "CmRegisterCallbackEx":              "Registry callback (Ex)",
            "ObRegisterCallbacks":               "Object-manager callback",
        }
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        for sec_va, sec_data in self.pe.get_code_sections():
            insns = self.dis.disassemble_range(sec_data, sec_va)
            # Track LEA results for resolving callback function pointers
            lea_targets: Dict[int, int] = {}

            for i, insn in enumerate(insns):
                if insn.mnemonic == "lea" and len(insn.operands) == 2:
                    dst, src = insn.operands
                    if (dst.type == x86c.X86_OP_REG and
                            src.type == x86c.X86_OP_MEM and
                            src.mem.base == x86c.X86_REG_RIP):
                        lea_targets[dst.reg] = insn.address + insn.size + src.mem.disp

                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                call_target = None
                if op.type == x86c.X86_OP_IMM:
                    call_target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                        op.mem.base == x86c.X86_REG_RIP and
                        op.mem.index == 0):
                    call_target = insn.address + insn.size + op.mem.disp
                if call_target is None or call_target not in self.pe.iat_map:
                    continue

                api_name = self.pe.iat_map[call_target]
                if api_name not in CALLBACK_APIS:
                    continue

                cb_desc = CALLBACK_APIS[api_name]
                # First arg (rcx) is typically the callback function pointer
                cb_va = lea_targets.get(x86c.X86_REG_RCX)
                if cb_va is None:
                    continue

                # Analyze what the callback does
                purpose = self._get_ioctl_purpose(cb_va)
                if purpose:
                    self.findings.append(Finding(
                        title=f"{cb_desc} at 0x{cb_va:X} performs '{purpose}'",
                        severity=Severity.HIGH,
                        description=f"Driver registers a {cb_desc} via {api_name}. "
                                    f"The callback at 0x{cb_va:X} performs '{purpose}'. "
                                    "This operation fires on every matching kernel event "
                                    "(e.g., every image load or process creation).",
                        location=f"0x{cb_va:X}",
                        details={"callback_api": api_name,
                                 "callback_va":  f"0x{cb_va:X}",
                                 "purpose":       purpose},
                    ))

    def scan_dse_disable(self):
        """Detect Driver Signature Enforcement (DSE) disabling patterns.
        When VBS is disabled, CI!g_CiOptions can be patched in memory to
        disable DSE, allowing unsigned drivers to load."""
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]
        has_resolve = "MmGetSystemRoutineAddress" in all_imports

        # Check for ci.dll / CI!g_CiOptions related strings in the binary
        ci_strings_found = []
        for sec in self.pe.pe.sections:
            sec_data = sec.get_data()
            # Check for Unicode "ci.dll", "CiInitialize", "g_CiOptions"
            for pattern, name in [
                (b"c\x00i\x00.\x00d\x00l\x00l", "ci.dll"),
                (b"C\x00i\x00I\x00n\x00i\x00t\x00i\x00a\x00l\x00i\x00z\x00e", "CiInitialize"),
                (b"g\x00_\x00C\x00i\x00O\x00p\x00t\x00i\x00o\x00n\x00s", "g_CiOptions"),
                (b"C\x00i\x00V\x00a\x00l\x00i\x00d\x00a\x00t\x00e", "CiValidate"),
                # ASCII versions
                (b"ci.dll", "ci.dll"),
                (b"g_CiOptions", "g_CiOptions"),
                (b"CiInitialize", "CiInitialize"),
            ]:
                if pattern in sec_data:
                    ci_strings_found.append(name)
            ci_strings_found = list(set(ci_strings_found))

        # Per-IOCTL detection via behavior analysis
        if self.ioctl_behaviors:
            for code, beh in self.ioctl_behaviors.items():
                api_names = {ac["name"] for ac in beh["api_calls"]}
                has_runtime_resolve = "MmGetSystemRoutineAddress" in api_names
                has_mem_write = any(ac["name"] in (
                    "MmCopyVirtualMemory", "ZwWriteVirtualMemory",
                    "NtWriteVirtualMemory")
                    for ac in beh["api_calls"])
                inline_ops = beh.get("inline_ops", [])
                has_inline_write = any(op.get("type") in ("MOV_MEM", "WRITE_MEM")
                                       for op in inline_ops)
                has_cr0_write = "__writecr0" in api_names

                # Pattern: runtime resolve + memory write + CI strings
                if (has_runtime_resolve and (has_mem_write or has_inline_write or has_cr0_write)
                        and ci_strings_found):
                    decoded = decode_ioctl(code)
                    self.findings.append(Finding(
                        title=f"DSE disable via IOCTL {decoded['code']}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IOCTL {decoded['code']} handler uses MmGetSystemRoutineAddress "
                            f"with CI-related strings ({', '.join(ci_strings_found)}) and "
                            f"performs kernel memory writes. This pattern resolves "
                            f"CI!g_CiOptions at runtime and patches it to disable Driver "
                            f"Signature Enforcement (DSE). Effective when VBS/HVCI is "
                            f"disabled — allows loading unsigned kernel drivers."
                        ),
                        location=f"0x{beh['handler_va']:X}",
                        poc_hint="dse_disable",
                        ioctl_code=code,
                        details={"ci_strings": ", ".join(ci_strings_found)},
                    ))
                # Also detect direct CR0.WP clearing (disables kernel write protection)
                elif has_cr0_write and ci_strings_found:
                    decoded = decode_ioctl(code)
                    self.findings.append(Finding(
                        title=f"DSE disable via CR0.WP + CI patch in IOCTL {decoded['code']}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IOCTL {decoded['code']} handler writes CR0 (disables WP bit) "
                            f"and references CI-related strings ({', '.join(ci_strings_found)}). "
                            f"Classic DSE bypass: clear CR0.WP → patch CI!g_CiOptions → "
                            f"restore CR0.WP. Only works with VBS disabled."
                        ),
                        location=f"0x{beh['handler_va']:X}",
                        poc_hint="dse_disable",
                        ioctl_code=code,
                    ))
            # Even without per-IOCTL match, flag CI strings + resolve at global level
            if ci_strings_found and has_resolve:
                self.findings.append(Finding(
                    title=f"DSE bypass capability: CI strings + MmGetSystemRoutineAddress",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Driver contains CI-related strings ({', '.join(ci_strings_found)}) "
                        f"and imports MmGetSystemRoutineAddress. This indicates capability "
                        f"to resolve and patch CI!g_CiOptions to disable DSE. "
                        f"Effective when VBS/HVCI is not enforced."
                    ),
                    location="Import Table + Data Sections",
                    poc_hint="dse_disable",
                    ioctl_code=self.ioctl_codes[0] if self.ioctl_codes else None,
                    details={"ci_strings": ", ".join(ci_strings_found)},
                ))
            return

        # Fallback: global detection
        if ci_strings_found and has_resolve:
            first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
            self.findings.append(Finding(
                title=f"DSE bypass pattern: CI strings ({', '.join(ci_strings_found)}) + runtime resolve",
                severity=Severity.CRITICAL,
                description=(
                    f"Driver references CI.dll internals ({', '.join(ci_strings_found)}) and "
                    f"can resolve kernel exports at runtime. This enables patching "
                    f"CI!g_CiOptions to disable Driver Signature Enforcement when VBS is "
                    f"disabled, allowing unsigned drivers to load."
                ),
                location="Import Table + Data Sections",
                poc_hint="dse_disable",
                ioctl_code=first_ioctl,
                details={"ci_strings": ", ".join(ci_strings_found)},
            ))

        # Also detect drivers that write CR0 + have CI strings (even without MmGetSystemRoutineAddress)
        if ci_strings_found and any(f in all_imports for f in ("__writecr0", "_writecr0")):
            first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
            self.findings.append(Finding(
                title="DSE bypass via CR0.WP disable + CI patching",
                severity=Severity.CRITICAL,
                description=(
                    f"Driver imports CR0 write capability and contains CI-related strings "
                    f"({', '.join(ci_strings_found)}). Pattern: disable CR0 Write Protect → "
                    f"patch CI!g_CiOptions → re-enable WP. Only effective when VBS disabled."
                ),
                location="Import Table + Data Sections",
                poc_hint="dse_disable",
                ioctl_code=first_ioctl,
            ))
