"""DispatcherFinder — discovers IOCTL dispatch functions by scanning all
executable sections for control-flow patterns that match compiler-generated
dispatchers.

When ``extract_major_functions`` fails (e.g. the driver sets MajorFunction
via a loop, memset, or Wdf wrapper), this module acts as a fallback by
looking for the dispatcher signature directly in code bytes.

Patterns recognised:
  1. Direct IoControlCode comparison
     cmp  [reg+0x18], 0x222000      ; IO_STACK_LOCATION->IoControlCode
     je   handler_A
  2. Register-cached comparison chain
     mov  eax, [reg+0x18]
     sub  eax, BASE
     je   handler_A
     sub  eax, DELTA
     je   handler_B
  3. Jump-table dispatch
     cmp  eax, N
     ja   default
     lea  rcx, [rip+table]
     movsxd rax, [rcx+rax*4]
     add  rax, rcx
     jmp  rax
  4. IOS field load + test/bitwise dispatch
     mov  eax, [reg+0x18]
     and  eax, mask
     cmp  eax, value
     je   handler

The module returns a list of ``(dispatcher_va, confidence)`` tuples.
Confidence is a heuristic score (higher = more likely to be the real
dispatcher).  The caller should try ``IOCTLDispatchCFG.reconstruct()`` on
the highest-confidence candidate first.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple

import capstone.x86_const as x86c

from drivertool.ioctl import is_valid_ioctl

logger = logging.getLogger(__name__)

# Offsets of IoControlCode in IO_STACK_LOCATION (x64 vs x86)
_IOS_IOCTL_OFFSETS = {0x18, 0x10}

# Minimum number of handler references before we consider something a dispatcher
_MIN_HANDLER_REFS = 2

# Maximum entries in a jump table before we consider it suspicious
_MAX_JUMP_TABLE_ENTRIES = 512


class DispatcherFinder:
    """Scan executable sections for likely IOCTL dispatch functions."""

    def __init__(self, pe_analyzer, disassembler):
        self.pe = pe_analyzer
        self.dis = disassembler
        self.image_base = pe_analyzer.pe.OPTIONAL_HEADER.ImageBase

    # ── Public API ───────────────────────────────────────────────────────

    def find_candidates(self) -> List[Tuple[int, float]]:
        """Return [(dispatcher_va, confidence), ...] sorted by confidence desc."""
        candidates: Dict[int, float] = {}

        for sec_va, sec_data in self.pe.get_code_sections():
            insns = self.dis.disassemble_range(sec_data, sec_va, max_insns=30000)
            if not insns:
                continue

            # Pattern 1 & 2: direct cmp/sub against IOS offsets or cached regs
            self._scan_cmp_sub_chains(insns, candidates)

            # Pattern 3: jump-table dispatch
            self._scan_jump_tables(insns, candidates)

            # Pattern 4: bitwise/test dispatch
            self._scan_bitwise_dispatch(insns, candidates)

        # Sort by confidence descending
        return sorted(candidates.items(), key=lambda x: x[1], reverse=True)

    # ── Pattern scanners ─────────────────────────────────────────────────

    def _scan_cmp_sub_chains(self, insns: list, candidates: Dict[int, float]):
        """Look for cmp/sub chains that compare against IOCTL-like values."""
        i = 0
        while i < len(insns):
            insn = insns[i]
            # Heuristic: instruction references IoControlCode field?
            refs_ios = self._insn_refs_ios_ioctl(insn)
            is_cmp_or_sub = insn.mnemonic in ("cmp", "sub")

            if is_cmp_or_sub and len(insn.operands) >= 2:
                op_imm = insn.operands[-1]
                if op_imm.type == x86c.X86_OP_IMM:
                    imm = op_imm.imm & 0xFFFFFFFF
                    if is_valid_ioctl(imm):
                        # Walk backwards to find function start / prologue
                        func_va = self._find_function_start(insns, i)
                        if func_va:
                            candidates[func_va] = candidates.get(func_va, 0) + 2.0

            elif refs_ios:
                # A mov/load from IOS field nearby a cmp is strong signal
                func_va = self._find_function_start(insns, i)
                if func_va:
                    candidates[func_va] = candidates.get(func_va, 0) + 1.5

            i += 1

    def _scan_jump_tables(self, insns: list, candidates: Dict[int, float]):
        """Look for indirect jumps preceded by bounds checks — classic switch."""
        for i, insn in enumerate(insns):
            if insn.mnemonic not in ("cmp", "test"):
                continue
            if len(insn.operands) < 2:
                continue
            op1 = insn.operands[1]
            if op1.type != x86c.X86_OP_IMM:
                continue
            bound = op1.imm & 0xFFFF
            if bound < 2 or bound > _MAX_JUMP_TABLE_ENTRIES:
                continue

            # Scan ahead for indirect jump
            found_jmp = False
            for j in range(i + 1, min(i + 16, len(insns))):
                ji = insns[j]
                if ji.mnemonic == "jmp" and ji.operands:
                    jop = ji.operands[0]
                    if jop.type == x86c.X86_OP_MEM or jop.type == x86c.X86_OP_REG:
                        found_jmp = True
                        break
                if ji.mnemonic in ("ret", "retn", "call"):
                    break

            if found_jmp:
                func_va = self._find_function_start(insns, i)
                if func_va:
                    # Jump tables in kernel code are very often dispatchers
                    candidates[func_va] = candidates.get(func_va, 0) + 3.0

    def _scan_bitwise_dispatch(self, insns: list, candidates: Dict[int, float]):
        """Look for and/mask + cmp or test + jnz patterns on IoControlCode."""
        for i, insn in enumerate(insns):
            if insn.mnemonic == "and" and len(insn.operands) == 2:
                op1 = insn.operands[1]
                if op1.type == x86c.X86_OP_IMM:
                    mask = op1.imm & 0xFFFFFFFF
                    # Common masks: 0xFFFFFFF8 (method), 0xFFFF (function)
                    if mask in (0xFFFFFFF8, 0xFFFFFFF0, 0xFFFF, 0xFFFC):
                        # Look ahead for cmp
                        for j in range(i + 1, min(i + 8, len(insns))):
                            ji = insns[j]
                            if ji.mnemonic in ("cmp", "test"):
                                func_va = self._find_function_start(insns, i)
                                if func_va:
                                    candidates[func_va] = candidates.get(func_va, 0) + 2.0
                                break
                            if ji.mnemonic in ("ret", "retn", "jmp", "call"):
                                break

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _insn_refs_ios_ioctl(insn) -> bool:
        """Return True if instruction loads from IO_STACK_LOCATION->IoControlCode."""
        if insn.mnemonic not in ("mov", "movzx", "movsx", "movsxd"):
            return False
        if len(insn.operands) < 2:
            return False
        src = insn.operands[1]
        if src.type != x86c.X86_OP_MEM:
            return False
        if src.mem.index != 0:
            return False
        return src.mem.disp in _IOS_IOCTL_OFFSETS

    @staticmethod
    def _find_function_start(insns: list, idx: int) -> Optional[int]:
        """Walk backwards from idx looking for a function prologue."""
        # Search up to 80 instructions back
        start = max(0, idx - 80)
        for j in range(idx, start - 1, -1):
            ji = insns[j]
            mn = ji.mnemonic
            # x64 prologue: sub rsp, N  or  push rbp ; mov rbp, rsp
            if mn == "sub" and len(ji.operands) == 2:
                dst = ji.operands[0]
                src = ji.operands[1]
                if (dst.type == x86c.X86_OP_REG and
                        dst.reg in (x86c.X86_REG_RSP, x86c.X86_REG_ESP) and
                        src.type == x86c.X86_OP_IMM):
                    return ji.address
            if mn == "push" and ji.operands:
                op = ji.operands[0]
                if op.type == x86c.X86_OP_REG and op.reg in (
                        x86c.X86_REG_RBP, x86c.X86_REG_EBP):
                    return ji.address
            # int3 padding or ud2 often precedes functions
            if mn in ("int3", "ud2") and j > 0 and insns[j - 1].mnemonic in ("int3", "ud2"):
                if j + 1 < len(insns):
                    return insns[j + 1].address
        # Fallback: use the instruction's own address if we can't find prologue
        if start <= idx < len(insns):
            return insns[start].address
        return None
