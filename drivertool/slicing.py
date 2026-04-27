"""Backward slicing at dangerous API call sites.

Forward taint says "user input *reaches* this argument." Backward
slicing answers the dual question: *given the value at this argument
right now, what controls it?* — by walking backward through the
instruction stream and collecting every instruction that contributes
to the value.

The output is a small structured ``ArgProvenance`` describing the
classification of each argument:

  - ``imm``                   : argument is a hard-coded immediate
  - ``mem_rip_fixed``         : argument loaded from a fixed RIP-relative
                                global / read-only constant
  - ``mem_stack_local``       : argument loaded from a local stack slot
                                that was set inside the function
  - ``mem_input_buffer``      : argument loaded from an offset of a known
                                user-buffer base register (the IRP / its
                                SystemBuffer chain)
  - ``register_from_caller``  : argument value is the function's own
                                input parameter (RCX/RDX/R8/R9 untouched)
  - ``api_return``            : argument is the return value of an
                                earlier call (e.g. ExAllocatePool result)
  - ``computed``              : argument is some arithmetic/transform
                                of one or more of the above
  - ``unknown``                : couldn't classify within the slice budget

This complements forward taint:
  - When forward taint says "tainted" + slicer says ``mem_input_buffer``
    → high-confidence proof of user control
  - When forward taint says "not tainted" + slicer says ``imm`` →
    high-confidence proof the arg is a constant
  - When the two disagree → flag for review
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import capstone.x86_const as x86c


# ──────────────────────────────────────────────────────────────────────────
# Public data model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class ArgProvenance:
    kind: str            # see module docstring
    detail: str = ""     # human-readable summary
    # Concrete fields populated based on `kind`:
    imm_value: Optional[int] = None          # for "imm"
    mem_disp: Optional[int] = None           # for "mem_*"
    mem_base_reg: Optional[int] = None
    src_register: Optional[int] = None       # for "register_from_caller"
    api_name: Optional[str] = None           # for "api_return"
    contributors: List[str] = field(default_factory=list)  # for "computed"


# ──────────────────────────────────────────────────────────────────────────
# Internal: register normalization (mirrors TaintTracker)
# ──────────────────────────────────────────────────────────────────────────

_R32_TO_R64 = {
    x86c.X86_REG_EAX: x86c.X86_REG_RAX, x86c.X86_REG_AX: x86c.X86_REG_RAX, x86c.X86_REG_AL: x86c.X86_REG_RAX,
    x86c.X86_REG_EBX: x86c.X86_REG_RBX, x86c.X86_REG_BX: x86c.X86_REG_RBX, x86c.X86_REG_BL: x86c.X86_REG_RBX,
    x86c.X86_REG_ECX: x86c.X86_REG_RCX, x86c.X86_REG_CX: x86c.X86_REG_RCX, x86c.X86_REG_CL: x86c.X86_REG_RCX,
    x86c.X86_REG_EDX: x86c.X86_REG_RDX, x86c.X86_REG_DX: x86c.X86_REG_RDX, x86c.X86_REG_DL: x86c.X86_REG_RDX,
    x86c.X86_REG_ESI: x86c.X86_REG_RSI, x86c.X86_REG_SI: x86c.X86_REG_RSI, x86c.X86_REG_SIL: x86c.X86_REG_RSI,
    x86c.X86_REG_EDI: x86c.X86_REG_RDI, x86c.X86_REG_DI: x86c.X86_REG_RDI, x86c.X86_REG_DIL: x86c.X86_REG_RDI,
    x86c.X86_REG_R8D: x86c.X86_REG_R8, x86c.X86_REG_R9D: x86c.X86_REG_R9,
    x86c.X86_REG_R10D: x86c.X86_REG_R10, x86c.X86_REG_R11D: x86c.X86_REG_R11,
    x86c.X86_REG_R12D: x86c.X86_REG_R12, x86c.X86_REG_R13D: x86c.X86_REG_R13,
    x86c.X86_REG_R14D: x86c.X86_REG_R14, x86c.X86_REG_R15D: x86c.X86_REG_R15,
}

def _c(reg: int) -> int:
    return _R32_TO_R64.get(reg, reg)


_ARG_REGS = (x86c.X86_REG_RCX, x86c.X86_REG_RDX,
             x86c.X86_REG_R8,  x86c.X86_REG_R9)

_VOLATILE = frozenset({
    x86c.X86_REG_RAX, x86c.X86_REG_RCX, x86c.X86_REG_RDX,
    x86c.X86_REG_R8,  x86c.X86_REG_R9,  x86c.X86_REG_R10,
    x86c.X86_REG_R11,
})


_REG_NAMES = {
    x86c.X86_REG_RCX: "RCX", x86c.X86_REG_RDX: "RDX",
    x86c.X86_REG_R8:  "R8",  x86c.X86_REG_R9:  "R9",
    x86c.X86_REG_RAX: "RAX",
}


def _reg_name(reg: int) -> str:
    return _REG_NAMES.get(_c(reg), f"reg{reg}")


# ──────────────────────────────────────────────────────────────────────────
# Backward slicer
# ──────────────────────────────────────────────────────────────────────────

class BackwardSlicer:
    """Walks instructions backward from a sink to classify each arg.

    Constructor receives the disassembled function body and the IAT map.
    Each call to ``slice_arg(call_idx, reg)`` performs a fresh walk
    backward from instruction index ``call_idx`` looking for the
    most-recent definition of ``reg``.
    """

    # Maximum backward steps for a single slice — prevents pathological
    # walks on large basic blocks without a clear def site.
    MAX_BACKWARD_STEPS = 60

    def __init__(self, insns: list, iat_map: Dict[int, str],
                 input_buffer_bases: Optional[Set[int]] = None):
        self.insns = insns
        self.iat_map = iat_map
        # Registers that we treat as roots of the user input buffer
        # chain. RCX (DeviceObject) is conservative; RDX (IRP) is the
        # canonical entry point for IRP_MJ_DEVICE_CONTROL on x64. Any
        # mov from these bases through a memory load is treated as a
        # "user buffer" source.
        self.input_buffer_bases = input_buffer_bases or {
            x86c.X86_REG_RDX, x86c.X86_REG_RCX,
        }

    # ── Public API ──────────────────────────────────────────────────

    def classify_call_args(self, call_idx: int,
                            arg_count: int = 4
                            ) -> List[ArgProvenance]:
        """Return a list of ArgProvenance for each of the first
        ``arg_count`` register arguments at the call instruction at
        ``self.insns[call_idx]``."""
        out: List[ArgProvenance] = []
        for i in range(arg_count):
            out.append(self.slice_arg(call_idx, _ARG_REGS[i]))
        return out

    def slice_arg(self, call_idx: int, target_reg: int) -> ArgProvenance:
        """Walk backward from ``call_idx`` looking for the definition
        of ``target_reg``. Returns its provenance."""
        target = _c(target_reg)
        steps = 0
        for i in range(call_idx - 1, max(call_idx - 1 - self.MAX_BACKWARD_STEPS, -1), -1):
            steps += 1
            insn = self.insns[i]
            mn = insn.mnemonic
            ops = insn.operands

            # Any earlier `call` clobbers volatile registers — if our
            # target is volatile and unset since, the value is the
            # return of that call.
            if mn == "call" and target in _VOLATILE:
                tgt = self._call_target(insn)
                if tgt is not None and tgt in self.iat_map:
                    return ArgProvenance(
                        kind="api_return",
                        api_name=self.iat_map[tgt],
                        detail=f"return value of {self.iat_map[tgt]}",
                    )
                # Internal-call return — generic "computed" tag
                return ArgProvenance(
                    kind="api_return",
                    detail="return value of internal function",
                )

            # Look for a write that defines `target`.
            if not ops:
                continue
            dst = ops[0]
            if dst.type != x86c.X86_OP_REG:
                continue
            if _c(dst.reg) != target:
                continue
            # Found the most recent definition of `target`.
            return self._classify_def(insn, i)

        # Fell off the end without finding a def → register holds its
        # original entry value (function parameter).
        if target in (_c(r) for r in _ARG_REGS):
            return ArgProvenance(
                kind="register_from_caller",
                src_register=target,
                detail=f"untouched from entry — {_reg_name(target)} parameter",
            )
        return ArgProvenance(kind="unknown",
                             detail="no def site within slice budget")

    # ── Classification of a single definition site ─────────────────

    def _classify_def(self, insn, idx: int) -> ArgProvenance:
        mn = insn.mnemonic
        ops = insn.operands

        # 1. mov reg, immediate
        if mn == "mov" and len(ops) == 2 and ops[1].type == x86c.X86_OP_IMM:
            return ArgProvenance(
                kind="imm",
                imm_value=ops[1].imm,
                detail=f"hard-coded {ops[1].imm:#x}",
            )

        # 2. xor reg, reg → zero
        if mn == "xor" and len(ops) == 2 and ops[0].reg == ops[1].reg:
            return ArgProvenance(
                kind="imm",
                imm_value=0,
                detail="zeroing idiom (xor reg, reg)",
            )

        # 3. lea reg, [rip + disp]  → fixed global address
        if mn == "lea" and len(ops) == 2 and ops[1].type == x86c.X86_OP_MEM:
            mem = ops[1].mem
            if mem.base == x86c.X86_REG_RIP and mem.index == 0:
                return ArgProvenance(
                    kind="mem_rip_fixed",
                    mem_disp=insn.address + insn.size + mem.disp,
                    detail=f"address of .rdata global {(insn.address + insn.size + mem.disp):#x}",
                )
            # lea reg, [rsp+disp] / [rbp+disp] — pointer to a local.
            # Used to pass an output buffer / OBJECT_ATTRIBUTES /
            # CLIENT_ID etc. Tag as stack-local pointer.
            if mem.base in (x86c.X86_REG_RSP, x86c.X86_REG_RBP):
                return ArgProvenance(
                    kind="mem_stack_local",
                    mem_base_reg=mem.base,
                    mem_disp=mem.disp,
                    detail=f"&local at [rsp+{mem.disp:#x}]",
                )
            # lea reg, [other_reg + disp] — derived from another reg
            if mem.base and mem.base not in (x86c.X86_REG_RIP,):
                base_prov = self.slice_arg(idx, mem.base)
                # If it's relative to a user-buffer base, surface that
                if (base_prov.kind == "register_from_caller" and
                        base_prov.src_register in self.input_buffer_bases):
                    return ArgProvenance(
                        kind="mem_input_buffer",
                        mem_base_reg=base_prov.src_register,
                        mem_disp=mem.disp,
                        detail=(f"&[{_reg_name(base_prov.src_register)}"
                                f"+{mem.disp:#x}] — pointer into user buffer"),
                    )
                if base_prov.kind == "mem_input_buffer":
                    return ArgProvenance(
                        kind="mem_input_buffer",
                        mem_disp=mem.disp,
                        detail=(f"&[+{mem.disp:#x}] off "
                                f"{base_prov.detail}"),
                    )
                return ArgProvenance(
                    kind="computed",
                    detail=f"{_reg_name(mem.base)}+{mem.disp:#x}",
                    contributors=[
                        f"base={base_prov.kind}({base_prov.detail})"],
                )

        # 4. mov reg, [base + disp]  → memory load
        if mn in ("mov", "movzx", "movsxd", "movsx") and len(ops) == 2:
            src = ops[1]
            if src.type == x86c.X86_OP_MEM:
                mem = src.mem
                # 4a. RIP-relative — fixed global / vtable / IAT slot
                if mem.base == x86c.X86_REG_RIP and mem.index == 0:
                    addr = insn.address + insn.size + mem.disp
                    api = self.iat_map.get(addr)
                    if api:
                        return ArgProvenance(
                            kind="api_return",
                            api_name=api,
                            detail=f"data import {api}",
                        )
                    return ArgProvenance(
                        kind="mem_rip_fixed",
                        mem_disp=addr,
                        detail=f"global qword at {addr:#x}",
                    )
                # 4b. Stack slot
                if mem.base in (x86c.X86_REG_RSP, x86c.X86_REG_RBP):
                    return ArgProvenance(
                        kind="mem_stack_local",
                        mem_base_reg=mem.base,
                        mem_disp=mem.disp,
                        detail=f"local at [rsp+{mem.disp:#x}]",
                    )
                # 4c. Pointer deref through some register
                if mem.base:
                    base_prov = self.slice_arg(idx, mem.base)
                    # If base_prov ultimately resolves to RDX/RCX entry
                    # parameter, treat the load as user-buffer derived.
                    if (base_prov.kind == "register_from_caller" and
                            base_prov.src_register in self.input_buffer_bases):
                        return ArgProvenance(
                            kind="mem_input_buffer",
                            mem_base_reg=base_prov.src_register,
                            mem_disp=mem.disp,
                            detail=(f"[{_reg_name(base_prov.src_register)}"
                                    f"+{mem.disp:#x}] — user buffer"),
                        )
                    if base_prov.kind == "mem_input_buffer":
                        return ArgProvenance(
                            kind="mem_input_buffer",
                            mem_disp=mem.disp,
                            detail=(f"chained deref [+{mem.disp:#x}]"
                                    f" off {base_prov.detail}"),
                        )
                    return ArgProvenance(
                        kind="computed",
                        detail=f"deref [{_reg_name(mem.base)}+{mem.disp:#x}]",
                        contributors=[
                            f"base={base_prov.kind}({base_prov.detail})"],
                    )

        # 5. mov reg, reg' — identity move; recurse on src
        if mn == "mov" and len(ops) == 2 and ops[1].type == x86c.X86_OP_REG:
            return self.slice_arg(idx, ops[1].reg)

        # 6. add/sub/imul/and/or/shl — arithmetic combination
        ARITH = ("add", "sub", "imul", "and", "or", "xor",
                 "shl", "shr", "sar", "rol", "ror", "neg", "not",
                 "inc", "dec")
        if mn in ARITH and len(ops) >= 2:
            dst_reg = ops[0].reg
            src_op = ops[1]
            dst_prov = self.slice_arg(idx, dst_reg)
            if src_op.type == x86c.X86_OP_IMM:
                src_desc = f"imm({src_op.imm:#x})"
            elif src_op.type == x86c.X86_OP_REG:
                src_p = self.slice_arg(idx, src_op.reg)
                src_desc = f"{src_p.kind}({src_p.detail})"
            else:
                src_desc = "mem"
            return ArgProvenance(
                kind="computed",
                detail=f"{mn} {dst_prov.kind} {src_desc}",
                contributors=[f"dst={dst_prov.kind}({dst_prov.detail})",
                              f"src={src_desc}"],
            )

        return ArgProvenance(kind="unknown", detail=f"def via {mn}")

    # ── helpers ─────────────────────────────────────────────────────

    def _call_target(self, insn) -> Optional[int]:
        if not insn.operands:
            return None
        op = insn.operands[0]
        if op.type == x86c.X86_OP_IMM:
            return op.imm
        if (op.type == x86c.X86_OP_MEM and
                op.mem.base == x86c.X86_REG_RIP and op.mem.index == 0):
            return insn.address + insn.size + op.mem.disp
        return None
