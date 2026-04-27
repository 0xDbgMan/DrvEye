from __future__ import annotations
import capstone
import capstone.x86_const as x86c
from typing import Dict, List, Optional, Tuple

import logging

logger = logging.getLogger(__name__)


class Disassembler:
    def __init__(self, is_64bit: bool):
        mode = capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.cs.detail = True
        self.is_64bit = is_64bit
        self._cache: Dict[Tuple[int, int, int], list] = {}

    def disassemble_range(self, code: bytes, base_addr: int, max_insns: int = 0) -> list:
        key = (base_addr, len(code), max_insns)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        try:
            result = list(self.cs.disasm(code, base_addr, count=max_insns))
        except Exception:
            logger.debug("Disassembly failed for range 0x%x (%d bytes)", base_addr, len(code), exc_info=True)
            result = []
        self._cache[key] = result
        return result

    def disassemble_function(self, code: bytes, base_addr: int, max_insns: int = 2000) -> list:
        insns = []
        for insn in self.cs.disasm(code, base_addr):
            insns.append(insn)
            if len(insns) >= max_insns:
                break
            if insn.mnemonic in ("ret", "retn", "int3") and len(insns) > 5:
                break
        return insns

    def extract_major_functions(self, code: bytes, base_addr: int,
                                 image_base: int) -> Dict[int, int]:
        """
        Scan DriverEntry and return {slot: handler_va} for every
        MajorFunction slot that is explicitly set.

        x64: DriverObject = rcx (first arg), MajorFunction[i] at +0x70 + i*8
        x86: MajorFunction[i] at +0x38 + i*4  (DriverObject tracked heuristically)

        Tracks:
          - lea reg, [rip+X]            -> reg holds function pointer X
          - mov reg, other_reg          -> propagate pointer / DriverObject ownership
          - mov [drv_reg + offset], reg -> write to MajorFunction slot
        """
        MF_BASE   = 0x70 if self.is_64bit else 0x38
        MF_STRIDE = 8    if self.is_64bit else 4
        MF_COUNT  = 28
        MF_END    = MF_BASE + MF_COUNT * MF_STRIDE

        insns = self.disassemble_range(code, base_addr, max_insns=1500)
        if not insns:
            return {}

        # reg_vals  : reg_id -> VA (handler function pointer in this reg)
        # drv_regs  : set of reg_ids currently holding the DriverObject pointer
        # drv_stack : set of normalized stack offsets where DriverObject was spilled
        #             (normalized = disp + rsp_adjust, relative to original RSP)
        reg_vals: Dict[int, int] = {}
        # x64: DriverObject = RCX (1st param)
        # x86: DriverObject = [esp+4] at entry — pushed to stack, often loaded via
        #       mov reg, [ebp+8] or mov reg, [esp+4+adjust] early in DriverEntry
        drv_regs: set = ({x86c.X86_REG_RCX} if self.is_64bit else set())
        drv_stack: set = set()
        rsp_adjust: int = 0  # cumulative RSP adjustment (negative = sub rsp)

        result: Dict[int, int] = {}

        # reg_imm: track registers holding small integer constants (for index computation)
        reg_imm: Dict[int, int] = {}

        # Canonicalize sub-registers to 64-bit parent (EAX->RAX, etc.)
        _sub_to_parent = {
            x86c.X86_REG_EAX: x86c.X86_REG_RAX, x86c.X86_REG_AX: x86c.X86_REG_RAX,
            x86c.X86_REG_AL: x86c.X86_REG_RAX, x86c.X86_REG_AH: x86c.X86_REG_RAX,
            x86c.X86_REG_EBX: x86c.X86_REG_RBX, x86c.X86_REG_BX: x86c.X86_REG_RBX,
            x86c.X86_REG_ECX: x86c.X86_REG_RCX, x86c.X86_REG_CX: x86c.X86_REG_RCX,
            x86c.X86_REG_EDX: x86c.X86_REG_RDX, x86c.X86_REG_DX: x86c.X86_REG_RDX,
            x86c.X86_REG_ESI: x86c.X86_REG_RSI, x86c.X86_REG_EDI: x86c.X86_REG_RDI,
            x86c.X86_REG_R8D: x86c.X86_REG_R8, x86c.X86_REG_R9D: x86c.X86_REG_R9,
            x86c.X86_REG_R10D: x86c.X86_REG_R10, x86c.X86_REG_R11D: x86c.X86_REG_R11,
            x86c.X86_REG_R12D: x86c.X86_REG_R12, x86c.X86_REG_R13D: x86c.X86_REG_R13,
            x86c.X86_REG_R14D: x86c.X86_REG_R14, x86c.X86_REG_R15D: x86c.X86_REG_R15,
        }
        def _cr(r: int) -> int:
            return _sub_to_parent.get(r, r)

        for insn in insns:
            # x86: detect DriverObject load from stack parameter [ebp+8]
            if (not self.is_64bit and insn.mnemonic == "mov" and
                    len(insn.operands) == 2):
                dst, src = insn.operands
                if (dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_MEM and
                        src.mem.base in (x86c.X86_REG_EBP,) and
                        src.mem.disp == 8 and src.mem.index == 0):
                    # mov reg, [ebp+8] — loading DriverObject (1st param in stdcall)
                    drv_regs.add(_cr(dst.reg))

            if insn.mnemonic == "lea" and len(insn.operands) == 2:
                dst, src = insn.operands
                if dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_MEM:
                    if self.is_64bit and src.mem.base == x86c.X86_REG_RIP:
                        addr = insn.address + insn.size + src.mem.disp
                        reg_vals[_cr(dst.reg)] = addr
                    elif (not self.is_64bit and src.mem.base == 0 and
                          src.mem.index == 0 and src.mem.disp != 0):
                        # x86: lea reg, [absolute_addr] — direct address load
                        reg_vals[_cr(dst.reg)] = src.mem.disp & 0xFFFFFFFF

            elif insn.mnemonic == "sub" and len(insn.operands) == 2:
                dst, src = insn.operands
                if (dst.type == x86c.X86_OP_REG and _cr(dst.reg) == x86c.X86_REG_RSP and
                        src.type == x86c.X86_OP_IMM):
                    rsp_adjust -= src.imm

            elif insn.mnemonic == "add" and len(insn.operands) == 2:
                dst, src = insn.operands
                if (dst.type == x86c.X86_OP_REG and _cr(dst.reg) == x86c.X86_REG_RSP and
                        src.type == x86c.X86_OP_IMM):
                    rsp_adjust += src.imm

            elif insn.mnemonic == "imul" and len(insn.operands) == 3:
                # imul rax, rax, IMM -> rax = rax * IMM (used for MF index)
                dst, src1, src2 = insn.operands
                if (dst.type == x86c.X86_OP_REG and
                        src1.type == x86c.X86_OP_REG and _cr(src1.reg) in reg_imm and
                        src2.type == x86c.X86_OP_IMM):
                    reg_imm[_cr(dst.reg)] = reg_imm[_cr(src1.reg)] * (src2.imm & 0xFFFFFFFF)

            elif insn.mnemonic == "mov" and len(insn.operands) == 2:
                dst, src = insn.operands

                # Propagate DriverObject register: mov reg, <drv_reg>
                if (dst.type == x86c.X86_OP_REG and
                        src.type == x86c.X86_OP_REG and _cr(src.reg) in drv_regs):
                    drv_regs.add(_cr(dst.reg))

                # Propagate known function pointer: mov reg, <known_reg>
                if (dst.type == x86c.X86_OP_REG and
                        src.type == x86c.X86_OP_REG and _cr(src.reg) in reg_vals):
                    reg_vals[_cr(dst.reg)] = reg_vals[_cr(src.reg)]

                # Load immediate into reg
                if dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_IMM:
                    val = src.imm & 0xFFFFFFFFFFFFFFFF
                    cr_dst = _cr(dst.reg)
                    reg_vals[cr_dst] = val
                    # Also track as small constant for imul index computation
                    if val <= 0xFFFF:
                        reg_imm[cr_dst] = val

                # Propagate small constants between registers
                if (dst.type == x86c.X86_OP_REG and
                        src.type == x86c.X86_OP_REG and _cr(src.reg) in reg_imm):
                    reg_imm[_cr(dst.reg)] = reg_imm[_cr(src.reg)]

                # Load from stack/memory into register — clear stale imm tracking
                if (dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_MEM):
                    cr_dst = _cr(dst.reg)
                    reg_imm.pop(cr_dst, None)

                # Store DriverObject to stack: mov [rsp+X], drv_reg
                if (dst.type == x86c.X86_OP_MEM and
                        src.type == x86c.X86_OP_REG and _cr(src.reg) in drv_regs and
                        _cr(dst.mem.base) in (x86c.X86_REG_RSP, x86c.X86_REG_RBP)):
                    # Normalize: store offset relative to original RSP
                    norm_off = dst.mem.disp + rsp_adjust if _cr(dst.mem.base) == x86c.X86_REG_RSP else dst.mem.disp
                    drv_stack.add(norm_off)

                # Reload DriverObject from stack: mov reg, [rsp+X]
                if (dst.type == x86c.X86_OP_REG and src.type == x86c.X86_OP_MEM and
                        _cr(src.mem.base) in (x86c.X86_REG_RSP, x86c.X86_REG_RBP)):
                    norm_off = src.mem.disp + rsp_adjust if _cr(src.mem.base) == x86c.X86_REG_RSP else src.mem.disp
                    if norm_off in drv_stack:
                        drv_regs.add(_cr(dst.reg))

                # MajorFunction slot write: mov [drv_reg + offset], handler_reg
                # Handles both [drv + disp] and [drv + index + disp] forms
                if dst.type == x86c.X86_OP_MEM and _cr(dst.mem.base) in drv_regs:
                    disp = dst.mem.disp
                    idx_val = 0
                    idx_reg = dst.mem.index
                    if idx_reg != 0 and _cr(idx_reg) in reg_imm:
                        idx_val = reg_imm[_cr(idx_reg)] * (dst.mem.scale if dst.mem.scale > 0 else 1)
                    off = disp + idx_val
                    if (MF_BASE <= off < MF_END and
                            (off - MF_BASE) % MF_STRIDE == 0):
                        slot = (off - MF_BASE) // MF_STRIDE
                        hva: Optional[int] = None
                        if src.type == x86c.X86_OP_REG and _cr(src.reg) in reg_vals:
                            hva = reg_vals[_cr(src.reg)]
                        elif src.type == x86c.X86_OP_IMM:
                            hva = src.imm
                        if hva:
                            result[slot] = hva

        return result

    def find_ioctl_dispatch_addr(self, code: bytes, base_addr: int,
                                  image_base: int) -> Optional[int]:
        """Thin wrapper — returns only IRP_MJ_DEVICE_CONTROL (slot 0xE)."""
        mf = self.extract_major_functions(code, base_addr, image_base)
        return mf.get(0x0E)

    def find_all_call_targets(self, insns: list) -> List[Tuple[int, int]]:
        """Return (insn_address, call_target) for direct calls."""
        targets = []
        for insn in insns:
            if insn.mnemonic == "call" and insn.operands:
                op = insn.operands[0]
                if op.type == x86c.X86_OP_IMM:
                    targets.append((insn.address, op.imm))
                elif op.type == x86c.X86_OP_MEM:
                    if self.is_64bit and op.mem.base == x86c.X86_REG_RIP:
                        addr = insn.address + insn.size + op.mem.disp
                        targets.append((insn.address, addr))
        return targets

    def find_function_prologues(self, va: int, data: bytes) -> List[int]:
        """
        Fast byte scan for x64 function entry points.
        Detects the two most common prologues:
          48 83 EC xx          — sub rsp, imm8
          48 81 EC xx xx xx xx — sub rsp, imm32
        Returns sorted list of VAs.
        """
        results: List[int] = []
        raw = bytes(data)
        n = len(raw)
        i = 0
        while i < n - 4:
            b0, b1, b2 = raw[i], raw[i + 1], raw[i + 2]
            if b0 == 0x48 and b1 in (0x83, 0x81) and b2 == 0xEC:
                results.append(va + i)
                i += 4
                continue
            i += 1
        return results
