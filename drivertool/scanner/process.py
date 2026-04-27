"""Process manipulation and privilege escalation scanning."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import capstone.x86_const as x86c

from drivertool.constants import Severity
from drivertool.ioctl import decode_ioctl
from drivertool.models import Finding

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ProcessScanMixin:
    """Mixin for process/privilege scans."""

    def scan_process_manipulation(self):
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]
        # Detect kill chains
        has_lookup = "PsLookupProcessByProcessId" in all_imports
        has_terminate = "ZwTerminateProcess" in all_imports
        has_open = "ZwOpenProcess" in all_imports
        has_attach = "KeAttachProcess" in all_imports or "KeStackAttachProcess" in all_imports

        if has_lookup and has_terminate:
            self.findings.append(Finding(
                title="Process kill chain: PsLookupProcessByProcessId -> ZwTerminateProcess",
                severity=Severity.HIGH,
                description="Driver can look up and terminate arbitrary processes. "
                            "If PID comes from user IOCTL, any process can be killed.",
                location="Import Table",
                poc_hint="process_kill",
            ))
        if has_lookup and has_attach:
            self.findings.append(Finding(
                title="Process attach chain: PsLookupProcessByProcessId -> KeAttachProcess",
                severity=Severity.HIGH,
                description="Driver can attach to arbitrary process contexts. "
                            "Enables cross-process memory access.",
                location="Import Table",
                poc_hint="process_attach",
            ))
        if has_open and has_terminate:
            self.findings.append(Finding(
                title="Process termination via ZwOpenProcess + ZwTerminateProcess",
                severity=Severity.HIGH,
                description="Driver can open and terminate arbitrary processes.",
                location="Import Table",
                poc_hint="process_kill",
            ))

    def scan_privilege_patterns(self):
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]
        # CR0/CR4 manipulation
        if "__writecr0" in all_imports:
            self.findings.append(Finding(
                title="CR0 write capability — Write Protection disable",
                severity=Severity.CRITICAL,
                description="Driver can write CR0, potentially disabling Write Protection (WP bit). "
                            "This allows modification of read-only kernel memory.",
                location="Import Table",
                poc_hint="cr_access",
            ))
        if "__writecr4" in all_imports:
            self.findings.append(Finding(
                title="CR4 write capability — SMEP/SMAP bypass",
                severity=Severity.CRITICAL,
                description="Driver can write CR4, potentially disabling SMEP and SMAP. "
                            "This defeats kernel exploit mitigations.",
                location="Import Table",
                poc_hint="cr_access",
            ))
        # MSR chain
        if "__readmsr" in all_imports and "__writemsr" in all_imports:
            self.findings.append(Finding(
                title="MSR read/write chain — Full kernel compromise",
                severity=Severity.CRITICAL,
                description="Driver can read and write Model-Specific Registers. "
                            "Writing IA32_LSTAR (0xC0000082) hijacks the syscall handler. "
                            "Writing to SMEP/SMAP bits in CR4 MSR disables mitigations.",
                location="Import Table",
                poc_hint="msr_readwrite",
            ))

    def scan_token_steal(self):
        """Detect EPROCESS token stealing pattern per IOCTL handler.
        Traces each handler to see if it accesses PsInitialSystemProcess,
        token APIs, and EPROCESS token offset writes."""
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]
        has_ps_initial = "PsInitialSystemProcess" in all_imports
        has_lookup = "PsLookupProcessByProcessId" in all_imports
        has_stricmp = "_stricmp" in all_imports or "stricmp" in all_imports

        # If no token-related imports at all, skip
        if not (has_ps_initial or has_lookup):
            return

        # Per-IOCTL token steal detection using behavior analysis
        if self.ioctl_behaviors:
            for code, beh in self.ioctl_behaviors.items():
                api_names = {ac["name"] for ac in beh["api_calls"]}
                has_token_api = api_names & {
                    "PsInitialSystemProcess", "PsReferencePrimaryToken",
                    "PsReferenceImpersonationToken", "ZwOpenProcessToken",
                    "ZwOpenProcessTokenEx", "ZwDuplicateToken", "NtDuplicateToken",
                }
                has_proc_resolve = api_names & {
                    "PsLookupProcessByProcessId", "ZwOpenProcess", "NtOpenProcess",
                }
                token_writes = beh.get("token_offset_writes", [])

                if has_token_api and has_proc_resolve:
                    decoded = decode_ioctl(code)
                    apis_str = ", ".join(sorted(has_token_api))
                    self.findings.append(Finding(
                        title=f"Token steal via IOCTL {decoded['code']}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IOCTL {decoded['code']} handler accesses {apis_str} and "
                            f"resolves target process. Classic token-steal pattern: "
                            f"copy SYSTEM token to attacker-controlled process."
                        ),
                        location=f"0x{beh['handler_va']:X}",
                        poc_hint="token_steal",
                        ioctl_code=code,
                    ))
                elif token_writes and has_proc_resolve:
                    decoded = decode_ioctl(code)
                    offsets = ", ".join(tw["offset"] for tw in token_writes[:3])
                    self.findings.append(Finding(
                        title=f"Token steal via IOCTL {decoded['code']} (offset write)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IOCTL {decoded['code']} handler writes to EPROCESS at "
                            f"token offsets ({offsets}) after resolving process by PID. "
                            f"Direct EPROCESS.Token overwrite pattern."
                        ),
                        location=f"0x{beh['handler_va']:X}",
                        poc_hint="token_steal",
                        ioctl_code=code,
                    ))
            return

        # Fallback: global import-based detection (no behavior data available)
        if has_ps_initial and has_stricmp:
            first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
            self.findings.append(Finding(
                title="Token steal pattern: PsInitialSystemProcess walk + _stricmp",
                severity=Severity.CRITICAL,
                description="Driver walks EPROCESS list from PsInitialSystemProcess using "
                            "_stricmp to match by process name. This is the classic "
                            "token-steal primitive: find privileged process, copy its "
                            "EPROCESS.Token to the target process.",
                location="Import Table",
                poc_hint="token_steal",
                ioctl_code=first_ioctl,
            ))

        if has_ps_initial and has_lookup:
            first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
            self.findings.append(Finding(
                title="Token steal chain: PsInitialSystemProcess + PsLookupProcessByProcessId",
                severity=Severity.CRITICAL,
                description="Driver can walk the EPROCESS list for a source process and use "
                            "PsLookupProcessByProcessId to resolve a target. Typical pattern "
                            "for copying SYSTEM token to an attacker-controlled process.",
                location="Import Table",
                poc_hint="token_steal",
                ioctl_code=first_ioctl,
            ))

    def scan_ppl_bypass(self):
        """Detect PPL bypass per IOCTL: single-byte write to EPROCESS.Protection."""
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]
        has_lookup = "PsLookupProcessByProcessId" in all_imports

        # Per-IOCTL PPL bypass detection using behavior analysis
        if self.ioctl_behaviors:
            for code, beh in self.ioctl_behaviors.items():
                ppl_writes = beh.get("ppl_byte_writes", [])
                api_names = {ac["name"] for ac in beh["api_calls"]}
                has_proc_resolve = api_names & {
                    "PsLookupProcessByProcessId", "ZwOpenProcess", "NtOpenProcess",
                }
                if ppl_writes and has_proc_resolve:
                    decoded = decode_ioctl(code)
                    offsets = ", ".join(pw["offset"] for pw in ppl_writes[:3])
                    self.findings.append(Finding(
                        title=f"PPL bypass via IOCTL {decoded['code']}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IOCTL {decoded['code']} handler resolves process by PID and "
                            f"writes a single byte at EPROCESS offset ({offsets}) — this is "
                            f"the PS_PROTECTION byte. Removes PPL/PP from any process "
                            f"including protected antimalware processes."
                        ),
                        location=f"0x{beh['handler_va']:X}",
                        poc_hint="ppl_bypass",
                        ioctl_code=code,
                        details={"eprocess_offsets": offsets},
                    ))
            return

        # Fallback: global scan (no behavior data available)
        ppl_write_found = False
        for va, data in self.pe.get_code_sections():
            insns = self.dis.disassemble_range(data, va, max_insns=3000)
            for insn in insns:
                if insn.mnemonic == "mov" and len(insn.operands) == 2:
                    dst = insn.operands[0]
                    if (dst.type == x86c.X86_OP_MEM and dst.size == 1 and
                            0x400 <= dst.mem.disp <= 0xA00):
                        ppl_write_found = True
                        break
            if ppl_write_found:
                break

        if has_lookup and ppl_write_found:
            first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
            self.findings.append(Finding(
                title="PPL bypass pattern: PsLookupProcessByProcessId + EPROCESS byte write",
                severity=Severity.CRITICAL,
                description="Driver resolves a process by PID (PsLookupProcessByProcessId) "
                            "and writes a single byte at a fixed EPROCESS offset — this is "
                            "the PS_PROTECTION byte. Allows removing PPL/PP from any process "
                            "including protected antimalware processes.",
                location="Import Table / Code",
                poc_hint="ppl_bypass",
                ioctl_code=first_ioctl,
                details={"eprocess_write": str(ppl_write_found)},
            ))

    def scan_edr_token_downgrade(self):
        """Detect EDR process token downgrade patterns.
        Lowering the integrity level or stripping privileges from an EDR's
        process token effectively neuters it without killing the process."""
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]
        has_lookup = "PsLookupProcessByProcessId" in all_imports
        has_token_set = any(f in all_imports for f in (
            "ZwSetInformationToken", "NtSetInformationToken",
            "ZwAdjustPrivilegesToken", "NtAdjustPrivilegesToken",
        ))

        # Per-IOCTL detection via behavior analysis
        if self.ioctl_behaviors:
            for code, beh in self.ioctl_behaviors.items():
                api_names = {ac["name"] for ac in beh["api_calls"]}
                has_proc_resolve = api_names & {
                    "PsLookupProcessByProcessId", "ZwOpenProcess", "NtOpenProcess",
                }
                has_token_open = api_names & {
                    "ZwOpenProcessToken", "ZwOpenProcessTokenEx",
                    "NtOpenProcessToken", "NtOpenProcessTokenEx",
                    "PsReferencePrimaryToken",
                }
                has_token_modify = api_names & {
                    "ZwSetInformationToken", "NtSetInformationToken",
                    "ZwAdjustPrivilegesToken", "NtAdjustPrivilegesToken",
                }
                # Token downgrade = resolve process + open token + modify token
                if has_proc_resolve and has_token_open and has_token_modify:
                    decoded = decode_ioctl(code)
                    modify_str = ", ".join(sorted(has_token_modify))
                    self.findings.append(Finding(
                        title=f"EDR token downgrade via IOCTL {decoded['code']}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IOCTL {decoded['code']} handler resolves a process, opens "
                            f"its token, and calls {modify_str}. This pattern is used to "
                            f"downgrade an EDR process's token: lowering integrity level "
                            f"from System to Low, stripping SeDebugPrivilege, or removing "
                            f"all privileges — effectively neutering the EDR without "
                            f"killing the process (which would trigger tamper protection)."
                        ),
                        location=f"0x{beh['handler_va']:X}",
                        poc_hint="edr_token_downgrade",
                        ioctl_code=code,
                    ))
                # Also detect direct EPROCESS token offset writes (manual downgrade)
                token_writes = beh.get("token_offset_writes", [])
                if token_writes and has_proc_resolve and not has_token_modify:
                    decoded = decode_ioctl(code)
                    offsets = ", ".join(tw["offset"] for tw in token_writes[:3])
                    self.findings.append(Finding(
                        title=f"EDR token manipulation via IOCTL {decoded['code']} (EPROCESS write)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IOCTL {decoded['code']} handler resolves a process and writes "
                            f"to EPROCESS at token-related offsets ({offsets}). This enables "
                            f"direct token manipulation: replacing or corrupting the EDR "
                            f"process's token to strip privileges."
                        ),
                        location=f"0x{beh['handler_va']:X}",
                        poc_hint="edr_token_downgrade",
                        ioctl_code=code,
                    ))
            return

        # Fallback: global import-based detection
        if has_lookup and has_token_set:
            token_apis = [f for f in all_imports
                          if f in ("ZwSetInformationToken", "NtSetInformationToken",
                                   "ZwAdjustPrivilegesToken", "NtAdjustPrivilegesToken")]
            first_ioctl = self.ioctl_codes[0] if self.ioctl_codes else None
            self.findings.append(Finding(
                title=f"EDR token downgrade pattern: process lookup + {', '.join(token_apis)}",
                severity=Severity.CRITICAL,
                description=(
                    f"Driver can resolve arbitrary processes and modify their tokens via "
                    f"{', '.join(token_apis)}. This enables downgrading EDR process tokens "
                    f"to remove privileges and reduce integrity level."
                ),
                location="Import Table",
                poc_hint="edr_token_downgrade",
                ioctl_code=first_ioctl,
            ))
