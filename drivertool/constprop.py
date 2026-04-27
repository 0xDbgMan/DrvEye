"""Lightweight forward constant propagation for x64.

Walks a linear instruction stream and folds register/stack-slot values
through ``mov``, ``add``, ``sub``, ``and``, ``or``, ``xor``, ``shl``,
``shr``, ``imul`` (×imm), ``lea`` (with constant base+index+disp).

The result is a per-instruction snapshot table answering
*"which registers and stack slots hold known constants right now?"* —
callers can read the snapshot at any instruction address.

Used for:
  - Bounds-check classification: at a ``cmp eax, X`` find the constant
    on either side and record the comparison.
  - Argument constancy: at a sink call, check whether each register
    arg holds a known constant.
  - Struct-offset reasoning: ``mov rax, [rcx+disp]`` where rcx is
    derived from a constant pointer is a fixed-offset deref.

Deliberately NOT a full SSA / value-set analysis. Single-path linear
propagation; loses precision at branches (a register's value is dropped
when branched/conditioned). Good enough for the leaf-block patterns we
care about.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import capstone.x86_const as x86c

from drivertool.slicing import _c, _reg_name


# ──────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class ValueState:
    """Constant-state snapshot at a single instruction.

    A register/slot maps to ``None`` if its value is unknown, or to an
    ``int`` (mod 2**64) if a concrete constant is known.
    """
    regs: Dict[int, int] = field(default_factory=dict)
    # Stack slots keyed by (base_reg, disp); mainly RSP/RBP.
    stack: Dict[Tuple[int, int], int] = field(default_factory=dict)

    def get_reg(self, reg: int) -> Optional[int]:
        return self.regs.get(_c(reg))

    def get_stack(self, base: int, disp: int) -> Optional[int]:
        return self.stack.get((_c(base), disp))

    def set_reg(self, reg: int, value: Optional[int]) -> None:
        canon = _c(reg)
        if value is None:
            self.regs.pop(canon, None)
        else:
            self.regs[canon] = value & 0xFFFFFFFFFFFFFFFF

    def set_stack(self, base: int, disp: int, value: Optional[int]) -> None:
        key = (_c(base), disp)
        if value is None:
            self.stack.pop(key, None)
        else:
            self.stack[key] = value & 0xFFFFFFFFFFFFFFFF

    def copy(self) -> "ValueState":
        return ValueState(regs=dict(self.regs), stack=dict(self.stack))


@dataclass
class BoundsCheck:
    """A ``cmp reg, K`` (or ``cmp K, reg``) detected during the pass.

    Records: address of the cmp, the register, and the constant it was
    compared against. Caller decides what the comparison meant given
    the immediately-following conditional branch (``ja`` ⇒ "above K is
    error" ⇒ value is constrained to ≤ K on the taken branch).
    """
    addr: int
    reg: int
    const: int
    cmp_kind: str  # "cmp" | "test"


# ──────────────────────────────────────────────────────────────────────────
# Forward propagation
# ──────────────────────────────────────────────────────────────────────────

# Volatile registers — clobbered across calls
_VOLATILE = frozenset({
    x86c.X86_REG_RAX, x86c.X86_REG_RCX, x86c.X86_REG_RDX,
    x86c.X86_REG_R8,  x86c.X86_REG_R9,  x86c.X86_REG_R10,
    x86c.X86_REG_R11,
})


def propagate(insns: list) -> Tuple[
        Dict[int, ValueState], List[BoundsCheck]]:
    """Walk instructions forward, tracking per-instruction value state.

    Returns (states_by_addr, bounds_checks).

    ``states_by_addr[ins.address]`` is the ValueState BEFORE that
    instruction executes. The state after the last instruction is
    accessible via ``states_by_addr.get(insns[-1].address + insns[-1].size)``
    if the caller needs the trailing state.
    """
    state = ValueState()
    states: Dict[int, ValueState] = {}
    bounds: List[BoundsCheck] = []

    for insn in insns:
        states[insn.address] = state.copy()
        mn = insn.mnemonic
        ops = insn.operands

        # ── Detect bounds checks (cmp/test) ─────────────────────────
        if mn in ("cmp", "test") and len(ops) == 2:
            a, b = ops
            if a.type == x86c.X86_OP_REG and b.type == x86c.X86_OP_IMM:
                bounds.append(BoundsCheck(
                    addr=insn.address, reg=_c(a.reg),
                    const=b.imm, cmp_kind=mn))
            elif a.type == x86c.X86_OP_IMM and b.type == x86c.X86_OP_REG:
                bounds.append(BoundsCheck(
                    addr=insn.address, reg=_c(b.reg),
                    const=a.imm, cmp_kind=mn))
            # cmp doesn't write a destination
            continue

        # ── MOV ────────────────────────────────────────────────────
        if mn in ("mov", "movzx", "movsxd", "movsx") and len(ops) == 2:
            dst, src = ops
            v = _eval_src(src, state, insn)
            if dst.type == x86c.X86_OP_REG:
                state.set_reg(dst.reg, v)
            elif dst.type == x86c.X86_OP_MEM and dst.mem.base in (
                    x86c.X86_REG_RSP, x86c.X86_REG_RBP):
                state.set_stack(dst.mem.base, dst.mem.disp, v)
            continue

        # ── LEA (constant arithmetic over base+index+disp) ─────────
        if mn == "lea" and len(ops) == 2 and ops[0].type == x86c.X86_OP_REG:
            dst, src = ops
            if src.type != x86c.X86_OP_MEM:
                state.set_reg(dst.reg, None); continue
            base_v: Optional[int] = None
            if src.mem.base == x86c.X86_REG_RIP:
                base_v = insn.address + insn.size
            elif src.mem.base:
                base_v = state.get_reg(src.mem.base)
            idx_v: Optional[int] = None
            if src.mem.index:
                rv = state.get_reg(src.mem.index)
                if rv is not None:
                    idx_v = rv * (src.mem.scale or 1)
            if base_v is None or (src.mem.index and idx_v is None):
                state.set_reg(dst.reg, None)
            else:
                state.set_reg(dst.reg, (base_v + (idx_v or 0) + src.mem.disp))
            continue

        # ── Arithmetic ─────────────────────────────────────────────
        if mn in ("add", "sub", "and", "or", "xor",
                  "shl", "shr", "sar", "imul") and len(ops) >= 2:
            dst, src = ops[0], ops[1]
            if dst.type != x86c.X86_OP_REG:
                continue
            cur = state.get_reg(dst.reg)
            if mn == "xor" and src.type == x86c.X86_OP_REG and src.reg == dst.reg:
                state.set_reg(dst.reg, 0); continue
            v_src: Optional[int] = None
            if src.type == x86c.X86_OP_IMM:
                v_src = src.imm
            elif src.type == x86c.X86_OP_REG:
                v_src = state.get_reg(src.reg)
            if cur is None or v_src is None:
                state.set_reg(dst.reg, None); continue
            if mn == "add":   r = cur + v_src
            elif mn == "sub": r = cur - v_src
            elif mn == "and": r = cur & v_src
            elif mn == "or":  r = cur | v_src
            elif mn == "xor": r = cur ^ v_src
            elif mn == "shl": r = cur << (v_src & 63)
            elif mn == "shr": r = (cur & 0xFFFFFFFFFFFFFFFF) >> (v_src & 63)
            elif mn == "sar":
                # signed right shift
                shift = v_src & 63
                if cur & (1 << 63):
                    r = -((-(cur)) >> shift)
                else:
                    r = cur >> shift
            elif mn == "imul":
                if len(ops) == 3 and ops[2].type == x86c.X86_OP_IMM:
                    r = (cur * ops[2].imm)
                else:
                    r = cur * v_src
            else:
                state.set_reg(dst.reg, None); continue
            state.set_reg(dst.reg, r & 0xFFFFFFFFFFFFFFFF)
            continue

        # ── INC / DEC ───────────────────────────────────────────────
        if mn in ("inc", "dec") and len(ops) == 1 and ops[0].type == x86c.X86_OP_REG:
            cur = state.get_reg(ops[0].reg)
            if cur is None:
                state.set_reg(ops[0].reg, None)
            else:
                state.set_reg(ops[0].reg, cur + (1 if mn == "inc" else -1))
            continue

        # ── CALL — clobber volatile regs ───────────────────────────
        if mn == "call":
            for r in _VOLATILE:
                state.set_reg(r, None)
            continue

        # ── Branches drop precision (we don't track per-path) ──────
        if mn.startswith("j") or mn in ("ret", "retn", "int3"):
            continue

        # ── Anything we don't model: clear writes-to register ──────
        if ops and ops[0].type == x86c.X86_OP_REG:
            state.set_reg(ops[0].reg, None)

    return states, bounds


def _eval_src(op, state: ValueState, insn) -> Optional[int]:
    """Evaluate a source operand at the given state. Returns int or None."""
    if op.type == x86c.X86_OP_IMM:
        return op.imm
    if op.type == x86c.X86_OP_REG:
        return state.get_reg(op.reg)
    if op.type == x86c.X86_OP_MEM:
        if op.mem.base == x86c.X86_REG_RIP and op.mem.index == 0:
            # RIP-relative — return the global's *address*. We don't
            # read the actual data, but address-as-constant is useful
            # for vtable / IAT-slot dereference reasoning downstream.
            return insn.address + insn.size + op.mem.disp
        if op.mem.base in (x86c.X86_REG_RSP, x86c.X86_REG_RBP) and op.mem.index == 0:
            return state.get_stack(op.mem.base, op.mem.disp)
    return None


# ──────────────────────────────────────────────────────────────────────────
# Bounds-check semantic interpretation
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class RegBound:
    """Inferred constraint on a register at a point in the code.

    ``op`` ∈ ``{"<=", "<", ">=", ">", "==", "!=", "unknown"}``
    ``const`` is the constant the register is constrained against.
    Encoded based on the conditional branch immediately following the
    cmp:

      cmp eax, 0x100; ja error  ⇒  on the fall-through path: eax ≤ 0x100
      cmp eax, 0x100; jb ok     ⇒  on the ok branch:        eax < 0x100

    Useful as a quick-and-dirty answer to *"is this length value
    constrained?"* without a full constraint solver.
    """
    addr: int
    reg: int
    op: str
    const: int


# Maps the conditional jump after a cmp to (taken-side, fallthrough-side)
# constraint. Each side describes "value is X relative to const".
_BRANCH_INTERPRETATION = {
    # unsigned
    "ja":  ("<=", ">"),    # jump if above   → taken: reg > const, fall: reg ≤ const
    "jae": ("<",  ">="),   # jump if above or equal
    "jb":  (">=", "<"),    # jump if below
    "jbe": (">",  "<="),
    "je":  ("!=", "=="),   # jump if equal
    "jne": ("==", "!="),
    "jz":  ("!=", "=="),
    "jnz": ("==", "!="),
    "jc":  (">=", "<"),    # CF=1 ≡ unsigned below (after cmp)
    "jnc": ("<",  ">="),
    # signed
    "jg":  ("<=", ">"),
    "jge": ("<",  ">="),
    "jl":  (">=", "<"),
    "jle": (">",  "<="),
}


def interpret_bounds(insns: list, bounds: List[BoundsCheck]
                     ) -> List[RegBound]:
    """Pair each bounds-check with the conditional branch that follows
    and produce a constraint describing the *fall-through* side
    (i.e. the path where the value is acceptable / not an error).

    Heuristic: the branch typically jumps to error on out-of-range, so
    the fall-through path is the validated path. When the branch jumps
    to the validated path instead, the constraint is reversed —
    callers should treat this as a hint, not proof.
    """
    out: List[RegBound] = []
    by_addr = {ins.address: i for i, ins in enumerate(insns)}
    for bc in bounds:
        idx = by_addr.get(bc.addr)
        if idx is None or idx + 1 >= len(insns):
            continue
        nxt = insns[idx + 1]
        interp = _BRANCH_INTERPRETATION.get(nxt.mnemonic)
        if interp is None:
            continue
        # We report the fallthrough constraint
        _, fallthrough_op = interp
        out.append(RegBound(
            addr=bc.addr, reg=bc.reg,
            op=fallthrough_op, const=bc.const,
        ))
    return out
