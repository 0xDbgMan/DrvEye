"""Z3-based constraint solving for IOCTL input discovery."""
from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import capstone.x86_const as x86c

from drivertool.constants import Severity
from drivertool.models import Finding
from drivertool.ioctl import decode_ioctl

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class Z3ScanMixin:
    """Mixin for Z3 constraint solving."""

    def _z3_encode_cmp_branch(self, cmp_insn, branch_insn, sym_regs,
                              sym_buf, taken: bool):
        """Encode a cmp+branch pair as a Z3 constraint. Returns constraint or None."""
        ops = cmp_insn.operands
        if len(ops) < 2:
            return None
        mn = branch_insn.mnemonic
        left = self._z3_operand_to_expr(cmp_insn, ops[0], sym_regs, sym_buf)
        right = self._z3_operand_to_expr(cmp_insn, ops[1], sym_regs, sym_buf)
        if left is None or right is None:
            return None
        return self._z3_branch_constraint(mn, left, right, taken)

    def _z3_operand_to_expr(self, insn, op, sym_regs, sym_buf):
        """Convert a capstone operand to a Z3 expression."""
        if op.type == x86c.X86_OP_IMM:
            return z3.BitVecVal(op.imm & 0xFFFFFFFFFFFFFFFF, 64)
        if op.type == x86c.X86_OP_REG:
            rn = self._canon_reg(insn.reg_name(op.reg))
            return sym_regs.get(rn)
        if op.type == x86c.X86_OP_MEM:
            base = insn.reg_name(op.mem.base) if op.mem.base else ""
            base = self._canon_reg(base) if base else ""
            disp = op.mem.disp
            # If base is a known buffer register, return buffer field
            if base in sym_regs and disp >= 0 and disp < 256:
                field_name = f"buf_{disp:#04x}"
                if field_name in sym_buf:
                    return sym_buf[field_name]
        return None

    def _z3_branch_constraint(self, mnemonic: str, left, right, taken: bool):
        """Build a Z3 constraint from branch mnemonic."""
        cmap_taken = {
            "je": lambda l, r: l == r,
            "jz": lambda l, r: l == r,
            "jne": lambda l, r: l != r,
            "jnz": lambda l, r: l != r,
            "jl": lambda l, r: l < r,
            "jb": lambda l, r: z3.ULT(l, r),
            "jle": lambda l, r: l <= r,
            "jbe": lambda l, r: z3.ULE(l, r),
            "jg": lambda l, r: l > r,
            "ja": lambda l, r: z3.UGT(l, r),
            "jge": lambda l, r: l >= r,
            "jae": lambda l, r: z3.UGE(l, r),
        }
        cmap_not_taken = {
            "je": lambda l, r: l != r,
            "jz": lambda l, r: l != r,
            "jne": lambda l, r: l == r,
            "jnz": lambda l, r: l == r,
            "jl": lambda l, r: l >= r,
            "jb": lambda l, r: z3.UGE(l, r),
            "jle": lambda l, r: l > r,
            "jbe": lambda l, r: z3.UGT(l, r),
            "jg": lambda l, r: l <= r,
            "ja": lambda l, r: z3.ULE(l, r),
            "jge": lambda l, r: l < r,
            "jae": lambda l, r: z3.ULT(l, r),
        }
        cm = cmap_taken if taken else cmap_not_taken
        fn = cm.get(mnemonic)
        return fn(left, right) if fn else None

    def _z3_collect_path_constraints(self, handler_va: int,
                                     sink_addr: int) -> Tuple[list, dict]:
        """Walk handler disassembly, collect Z3 constraints toward sink_addr."""
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        rva = handler_va - image_base
        code = self.pe.get_bytes_at_rva(rva, 0x2000)
        if not code:
            return [], {}
        insns = self.dis.disassemble_function(code, handler_va, max_insns=500)
        if not insns:
            return [], {}
        # Create symbolic buffer fields (generic 256-byte buffer, 8 bytes each)
        sym_buf: Dict[str, object] = {}
        for off in range(0, 256, 4):
            name = f"buf_{off:#04x}"
            sym_buf[name] = z3.BitVec(name, 64)
        # Symbolic registers
        sym_regs: Dict[str, object] = {}
        # Track: IRP in rdx → SystemBuffer
        sym_regs["rdx"] = z3.BitVec("irp", 64)
        constraints = []
        constraint_strs = []
        prev_cmp = None
        for insn in insns:
            mn = insn.mnemonic
            ops = insn.operands
            # Track mov/lea propagation into symbolic registers
            if mn in ("mov", "lea", "movzx", "movsx") and len(ops) == 2:
                dst, src = ops[0], ops[1]
                if dst.type == x86c.X86_OP_REG:
                    dn = self._canon_reg(insn.reg_name(dst.reg))
                    expr = self._z3_operand_to_expr(insn, src, sym_regs, sym_buf)
                    if expr is not None:
                        sym_regs[dn] = expr
            elif mn in ("cmp", "test"):
                prev_cmp = insn
            elif mn.startswith("j") and mn != "jmp" and prev_cmp:
                # Determine if this branch leads toward the sink
                target = None
                if ops and ops[0].type == x86c.X86_OP_IMM:
                    target = ops[0].imm
                # Heuristic: if the branch skips past sink, take fall-through
                taken = target is not None and target <= sink_addr
                if prev_cmp.mnemonic == "test":
                    # test reg, reg; jz → reg == 0
                    test_ops = prev_cmp.operands
                    if (len(test_ops) == 2
                            and test_ops[0].type == x86c.X86_OP_REG
                            and test_ops[1].type == x86c.X86_OP_REG):
                        rn = self._canon_reg(
                            prev_cmp.reg_name(test_ops[0].reg))
                        if rn in sym_regs:
                            val = sym_regs[rn]
                            zero = z3.BitVecVal(0, 64)
                            c = self._z3_branch_constraint(
                                mn, val, zero, taken)
                            if c is not None:
                                constraints.append(c)
                                constraint_strs.append(
                                    f"{rn} {'==' if taken and mn in ('jz','je') else '!='} 0")
                else:
                    c = self._z3_encode_cmp_branch(
                        prev_cmp, insn, sym_regs, sym_buf, taken)
                    if c is not None:
                        constraints.append(c)
                        constraint_strs.append(
                            f"branch@0x{insn.address:x} "
                            f"({'taken' if taken else 'not-taken'})")
                prev_cmp = None
            else:
                if mn != "nop":
                    prev_cmp = None
        return constraints, sym_buf

    def solve_ioctl_constraints(self):
        """Use Z3 to compute exact input bytes that trigger vulnerability paths."""
        if not Z3_AVAILABLE:
            return
        if not self.taint_paths:
            return
        for tp in self.taint_paths:
            code = tp["ioctl"]
            handler_va = self._get_handler_va(code)
            if not handler_va:
                continue
            sink_addr = tp.get("sink_addr", 0)
            try:
                constraints, sym_buf = self._z3_collect_path_constraints(
                    handler_va, sink_addr)
            except Exception:
                continue
            if not constraints:
                continue
            solver = z3.Solver()
            solver.set("timeout", 5000)  # 5 second timeout
            for c in constraints:
                solver.add(c)
            result = solver.check()
            entry: dict = {
                "ioctl": code,
                "sink": tp["sink"],
                "satisfiable": result == z3.sat,
                "constraints": [],
                "trigger_input": {},
                "raw_bytes": b"",
            }
            if result == z3.sat:
                model = solver.model()
                raw = bytearray(256)
                trigger: Dict[str, int] = {}
                for name, bv in sym_buf.items():
                    val = model.eval(bv, model_completion=True)
                    try:
                        int_val = val.as_long()
                    except Exception:
                        int_val = 0
                    trigger[name] = int_val
                    # Extract offset from name like "buf_0x0c"
                    try:
                        off = int(name.split("_")[1], 16)
                    except (IndexError, ValueError):
                        continue
                    if off + 4 <= 256:
                        struct.pack_into("<I", raw, off, int_val & 0xFFFFFFFF)
                entry["trigger_input"] = trigger
                entry["raw_bytes"] = bytes(raw)
                entry["constraints"] = [str(c) for c in constraints]
                self.z3_solutions.append(entry)
                # Build hex preview of non-zero trigger fields
                active = {k: f"0x{v:X}" for k, v in trigger.items() if v}
                self.findings.append(Finding(
                    title=f"Z3: concrete input triggers {tp['sink']}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Z3 solver found concrete IOCTL input buffer "
                        f"(code 0x{code:08X}) that reaches {tp['sink']}.\n\n"
                        f"Trigger values:\n"
                        + "\n".join(f"  {k} = {v}" for k, v in
                                   sorted(active.items())[:10])
                        + f"\n\nRaw bytes (first 32): "
                        f"{bytes(raw[:32]).hex()}"
                    ),
                    location=f"0x{sink_addr:X}",
                    details={
                        "sink": tp["sink"],
                        "satisfiable": "True",
                        "num_constraints": str(len(constraints)),
                        "raw_hex": bytes(raw[:64]).hex(),
                    },
                    poc_hint=self._taint_poc_hint(tp["sink"]),
                    ioctl_code=code,
                ))
            elif result == z3.unsat:
                entry["satisfiable"] = False
                self.z3_solutions.append(entry)
                self.findings.append(Finding(
                    title=f"Z3: path to {tp['sink']} is infeasible",
                    severity=Severity.INFO,
                    description=(
                        f"Z3 proved the taint path to {tp['sink']} "
                        f"(IOCTL 0x{code:08X}) is unsatisfiable — "
                        f"likely a false positive from taint analysis."
                    ),
                    location=f"0x{sink_addr:X}",
                    details={
                        "sink": tp["sink"],
                        "satisfiable": "False",
                        "num_constraints": str(len(constraints)),
                    },
                    ioctl_code=code,
                ))
            # z3.unknown — timeout, skip silently
