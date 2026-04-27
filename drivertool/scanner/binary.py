"""Binary structure and kernel patching detection."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List

import capstone.x86_const as x86c

from drivertool.constants import Severity
from drivertool.models import Finding

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class BinaryScanMixin:
    """Mixin for binary structure scans."""

    def scan_section_anomalies(self):
        for sec in self.pe.sections:
            name = sec["name"]
            # W+X
            if sec["writable"] and sec["executable"]:
                self.findings.append(Finding(
                    title=f"Section '{name}' is Writable + Executable (W+X)",
                    severity=Severity.HIGH,
                    description="Section has both write and execute permissions. "
                                "This is a strong indicator of self-modifying code or packing.",
                    location=f"Section: {name}",
                ))
            # High entropy
            if sec["entropy"] > 7.0:
                self.findings.append(Finding(
                    title=f"Section '{name}' has high entropy ({sec['entropy']:.2f})",
                    severity=Severity.MEDIUM,
                    description="Entropy above 7.0 suggests encrypted or compressed content. "
                                "The section may be packed or contain obfuscated code.",
                    location=f"Section: {name}",
                    details={"entropy": f"{sec['entropy']:.2f}"},
                ))

    def scan_ssdt_hooks(self):
        """
        Detect two kernel-patching patterns:
        1. CR0 WP-bit clear: AND reg, 0xFFFEFFFF before __writecr0
           — disables page write protection to allow SSDT/IDT patching.
        2. KeServiceDescriptorTable string reference — SSDT manipulation.
        """
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        # ── Pattern 1: CR0 WP-bit disable ────────────────────────────────
        has_writecr0 = any("__writecr0" in funcs
                           for funcs in self.pe.imports.values())
        if has_writecr0:
            for sec_va, sec_data in self.pe.get_code_sections():
                insns = self.dis.disassemble_range(sec_data, sec_va)
                for insn in insns:
                    if insn.mnemonic == "and" and len(insn.operands) == 2:
                        op1 = insn.operands[1]
                        if op1.type == x86c.X86_OP_IMM:
                            imm = op1.imm & 0xFFFFFFFF
                            # Bit 16 of CR0 is the WP bit; masking it out = 0xFFFEFFFF
                            if imm == 0xFFFEFFFF:
                                self.findings.append(Finding(
                                    title="CR0 WP-bit clear — kernel write protection disabled",
                                    severity=Severity.CRITICAL,
                                    description="Driver clears the Write Protect (WP) bit in "
                                                "CR0 (AND reg, 0xFFFEFFFF before __writecr0). "
                                                "This disables hardware write protection on "
                                                "read-only kernel pages, enabling SSDT hooks, "
                                                "IDT patches, or arbitrary kernel memory writes.",
                                    location=f"0x{insn.address:X}",
                                    poc_hint="cr_access",
                                    details={"address": f"0x{insn.address:X}"},
                                ))
                                break  # one finding per section is enough

        # ── Pattern 2: KeServiceDescriptorTable reference ─────────────────
        ssdt_ascii = b"KeServiceDescriptorTable"
        ssdt_wide  = b"K\x00e\x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00D\x00"
        if ssdt_ascii in self.pe.raw or ssdt_wide in self.pe.raw:
            self.findings.append(Finding(
                title="KeServiceDescriptorTable reference (SSDT hook indicator)",
                severity=Severity.CRITICAL,
                description="Driver contains a string reference to "
                            "KeServiceDescriptorTable — the System Service Descriptor "
                            "Table. Direct access to this structure is the canonical "
                            "method for hooking Windows system calls (SSDT hooking), "
                            "a rootkit-grade technique.",
                location="Binary strings",
                details={"symbol": "KeServiceDescriptorTable"},
            ))

    def scan_hidden_functions(self):
        """
        Build a complete function list via prologue scan and run purpose
        detection on functions that are NOT reachable from DriverEntry's
        normal call graph.  Surfaces hidden dispatch routines, covert kill
        callbacks, and secondary attack-surface paths.
        """
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        # Collect all functions the normal analysis already touched
        known: set = set()
        ep_addr, ep_bytes = self.pe.get_entry_point_bytes(count=1024)
        if ep_bytes:
            known.add(ep_addr)
            mf = self.dis.extract_major_functions(ep_bytes, ep_addr, image_base)
            known.update(mf.values())

        # Prologue scan across all executable sections
        all_funcs: List[int] = []
        for sec_va, sec_data in self.pe.get_code_sections():
            all_funcs.extend(self.dis.find_function_prologues(sec_va, sec_data))

        checked = 0
        for fn_va in all_funcs:
            if fn_va in known:
                continue
            purpose = self._get_ioctl_purpose(fn_va)
            if purpose:
                known.add(fn_va)
                checked += 1
                self.findings.append(Finding(
                    title=f"Hidden function with purpose '{purpose}' at 0x{fn_va:X}",
                    severity=Severity.HIGH,
                    description=f"Function at 0x{fn_va:X} performs '{purpose}' but is "
                                "not reachable via the normal DriverEntry → MajorFunction "
                                "call graph.  It may be invoked via a timer, DPC, work "
                                "item, or kernel callback — a hidden secondary attack path.",
                    location=f"0x{fn_va:X}",
                    details={"purpose": purpose, "function": f"0x{fn_va:X}"},
                ))
            if checked >= 32:   # cap to avoid excessive output
                break

    def scan_dkom_patterns(self):
        """
        Detect Direct Kernel Object Manipulation patterns in disassembly:
        - EPROCESS ActiveProcessLinks walk (process hiding/enumeration)
        - Token field copy (token stealing for privilege escalation)

        Looks for loops with [reg+offset] access patterns at known
        EPROCESS offsets across multiple Windows builds.
        """
        # Known EPROCESS offsets per Windows build
        # (UniqueProcessId, ActiveProcessLinks, Token)
        OFFSETS = {
            "Win10_1507":  (0x2E8, 0x2F0, 0x358),
            "Win10_1607":  (0x2E8, 0x2F0, 0x358),
            "Win10_1803":  (0x2E0, 0x2E8, 0x358),
            "Win10_1903":  (0x2E8, 0x2F0, 0x360),
            "Win10_2004":  (0x440, 0x448, 0x4B8),
            "Win10_21H2":  (0x440, 0x448, 0x4B8),
            "Win11_22H2":  (0x440, 0x448, 0x4B8),
            "Win11_23H2":  (0x440, 0x448, 0x4B8),
        }

        # Collect all memory access offsets from code sections
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        access_offsets: set = set()

        for sec_va, sec_data in self.pe.get_code_sections():
            insns = self.dis.disassemble_range(sec_data, sec_va)
            for insn in insns:
                if insn.mnemonic in ("mov", "lea", "cmp") and len(insn.operands) == 2:
                    for op in insn.operands:
                        if op.type == x86c.X86_OP_MEM and op.mem.disp > 0x100:
                            access_offsets.add(op.mem.disp & 0xFFFF)

        # Check if code accesses known EPROCESS offset triples
        for build, (pid_off, links_off, token_off) in OFFSETS.items():
            has_pid   = pid_off   in access_offsets
            has_links = links_off in access_offsets
            has_token = token_off in access_offsets

            if has_links and has_token:
                self.findings.append(Finding(
                    title=f"DKOM: EPROCESS walk + token steal pattern ({build} offsets)",
                    severity=Severity.CRITICAL,
                    description=f"Driver accesses EPROCESS offsets for ActiveProcessLinks "
                                f"({links_off:#x}) and Token ({token_off:#x}), matching "
                                f"{build} layout. This is the classic token-stealing "
                                "privilege escalation pattern: walk the EPROCESS linked "
                                "list, find System process, copy its token to the target.",
                    location="Code sections",
                    details={"build": build,
                             "pid_offset": f"{pid_off:#x}",
                             "links_offset": f"{links_off:#x}",
                             "token_offset": f"{token_off:#x}"},
                ))
                break  # one match is enough

            if has_links and has_pid and not has_token:
                self.findings.append(Finding(
                    title=f"DKOM: EPROCESS list walk pattern ({build} offsets)",
                    severity=Severity.HIGH,
                    description=f"Driver accesses EPROCESS ActiveProcessLinks ({links_off:#x}) "
                                f"and UniqueProcessId ({pid_off:#x}), matching {build} layout. "
                                "This suggests EPROCESS enumeration (process hiding or targeting).",
                    location="Code sections",
                    details={"build": build,
                             "pid_offset": f"{pid_off:#x}",
                             "links_offset": f"{links_off:#x}"},
                ))
                break
