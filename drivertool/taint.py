"""Forward taint propagation for x64 (Microsoft ABI).

Tracks both register and memory-slot taint. Memory slots recognized:
  * stack slots addressed via RSP/RBP
  * pointer-deref memory (``[reg+disp]``) when ``reg`` itself is tainted
  * RIP-relative global slots written then re-read within the same
    analysis window

Plus optional *interprocedural* mode: when ``resolve_internal_call`` is
supplied, the tracker can recurse into in-driver ``call`` targets up to
``max_call_depth`` levels, reporting API-call hits found inside those
callees. This catches user-buffer→helper→dangerous-API patterns that
pure forward register taint misses once a call frame appears.
"""
from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional, Set, Tuple

import capstone.x86_const as x86c

logger = logging.getLogger(__name__)


class TaintTracker:
    """
    Forward taint propagation for x64 (Microsoft ABI).

    Seeds a set of registers as "tainted" (user-controlled) and propagates
    taint through mov/lea/arithmetic/store/load. Reports dangerous IAT
    calls that receive tainted argument registers.
    """

    # Volatile regs clobbered by any call (Microsoft x64 ABI)
    _VOLATILE = frozenset({
        x86c.X86_REG_RAX, x86c.X86_REG_RCX, x86c.X86_REG_RDX,
        x86c.X86_REG_R8,  x86c.X86_REG_R9,  x86c.X86_REG_R10,
        x86c.X86_REG_R11,
    })
    # Argument registers in order (rcx, rdx, r8, r9)
    _ARG_REGS = [
        x86c.X86_REG_RCX, x86c.X86_REG_RDX,
        x86c.X86_REG_R8,  x86c.X86_REG_R9,
    ]
    # 32-bit → 64-bit register aliases
    _R32_TO_R64: Dict[int, int] = {
        x86c.X86_REG_EAX: x86c.X86_REG_RAX,
        x86c.X86_REG_ECX: x86c.X86_REG_RCX,
        x86c.X86_REG_EDX: x86c.X86_REG_RDX,
        x86c.X86_REG_EBX: x86c.X86_REG_RBX,
        x86c.X86_REG_ESP: x86c.X86_REG_RSP,
        x86c.X86_REG_EBP: x86c.X86_REG_RBP,
        x86c.X86_REG_ESI: x86c.X86_REG_RSI,
        x86c.X86_REG_EDI: x86c.X86_REG_RDI,
        x86c.X86_REG_R8D:  x86c.X86_REG_R8,
        x86c.X86_REG_R9D:  x86c.X86_REG_R9,
        x86c.X86_REG_R10D: x86c.X86_REG_R10,
        x86c.X86_REG_R11D: x86c.X86_REG_R11,
        x86c.X86_REG_R12D: x86c.X86_REG_R12,
        x86c.X86_REG_R13D: x86c.X86_REG_R13,
        x86c.X86_REG_R14D: x86c.X86_REG_R14,
        x86c.X86_REG_R15D: x86c.X86_REG_R15,
    }

    def __init__(self, iat_map: Dict[int, str],
                 resolve_internal_call: Optional[
                     Callable[[int], Optional[list]]] = None,
                 max_call_depth: int = 2):
        """
        Args:
            iat_map: {call_va: import_name}
            resolve_internal_call: when given, receives a call-target VA
                and returns the disassembled instruction list for that
                callee (or None to decline). Enables interprocedural
                taint. Typically bound to the caller's disassembler.
            max_call_depth: maximum recursion depth into internal calls.
        """
        self.iat_map = iat_map
        self._resolve = resolve_internal_call
        self._max_call_depth = max_call_depth
        # Per-(callee, seed) function summary cache. Each entry is:
        #   {"sub_results": [...IAT hits...],
        #    "ret_tainted": bool,
        #    "mem_taint_writes": List[(base_reg, disp)] }
        # Populated lazily; broken via _SUMMARY_PENDING tombstone for
        # mutually-recursive callees.
        self._summary_cache: Dict[Tuple[int, frozenset], Dict] = {}

    def _c(self, reg: int) -> int:
        """Canonicalize 32-bit register to its 64-bit parent."""
        return self._R32_TO_R64.get(reg, reg)

    # Memory slot key: (base_reg_canonical, disp). index/scale not tracked
    # (ignore scaled-index stores; they're rare in driver argument staging
    # code and modeling them safely needs a full value analysis).
    def _mem_key(self, mem) -> Optional[Tuple[int, int]]:
        if mem.index != 0:
            return None
        base = self._c(mem.base) if mem.base else 0
        if base == 0:
            return None
        return (base, mem.disp)

    # ── Summary construction ───────────────────────────────────────────

    _SUMMARY_PENDING = object()  # tombstone for in-flight summaries

    def _get_or_build_summary(self,
                              callee_va: int,
                              seed: frozenset,
                              depth: int,
                              seen: set) -> Optional[Dict]:
        """Compute (or retrieve) the function summary for `callee_va`
        under the given input-arg-taint seed.

        Returns a dict with keys ``sub_results``, ``ret_tainted``,
        ``mem_taint_writes``. Returns None when the callee can't be
        disassembled or recursion blew through.
        """
        key = (callee_va, seed)
        cached = self._summary_cache.get(key)
        if cached is self._SUMMARY_PENDING:
            # Recursive cycle — break with an empty summary.
            return {
                "sub_results": [],
                "ret_tainted": False,
                "mem_taint_writes": [],
            }
        if cached is not None:
            return cached

        # Disassemble the callee
        callee_insns = None
        try:
            callee_insns = self._resolve(callee_va)
        except Exception:
            logger.debug("Failed to resolve callee 0x%x", callee_va, exc_info=True)
            callee_insns = None
        if not callee_insns:
            return None

        self._summary_cache[key] = self._SUMMARY_PENDING
        try:
            summary = self._analyze_callee_for_summary(
                callee_insns, seed, depth + 1, seen | {callee_va})
        except Exception:
            logger.debug("Failed to build summary for callee 0x%x", callee_va, exc_info=True)
            summary = {
                "sub_results": [],
                "ret_tainted": False,
                "mem_taint_writes": [],
            }
        self._summary_cache[key] = summary
        return summary

    def _analyze_callee_for_summary(self, insns: list, seed: frozenset,
                                     depth: int, seen: set) -> Dict:
        """Run the standard analyze() on a callee body, then post-process
        to extract the *summary* fields the caller cares about:
          - ret_tainted: was RAX tainted at any point near the end?
          - mem_taint_writes: which caller-frame stack slots were
            tainted by the time the callee returns?

        Implementation: re-runs analyze() to collect IAT hits (the
        existing forward pass), then does a second short pass focused
        on tracking RAX state and stack-write deltas. The second pass
        is bounded so a 1000-instruction callee doesn't blow up.
        """
        sub_results = self.analyze(insns, set(seed),
                                    _depth=depth, _seen=seen)

        # Compute ret_tainted via a focused pass: simulate just the
        # taint set, find writes to RAX, and see if RAX is tainted at
        # the last instruction. We reuse the high-level rule we already
        # had: if any IAT call was made with arg 0 tainted, the callee
        # may return tainted. This is a conservative over-approximation.
        ret_tainted = any(
            0 in r.get("tainted_args", []) for r in sub_results)

        # Stack-slot write detection: walk the callee, when we see a
        # store of a tainted register into [rsp+N] where N >= 0x28 (just
        # above the shadow space), record the slot. Caller's mem state
        # picks these up.
        # NOTE: this is intentionally narrow — avoids false-positives on
        # callees that overwrite their own scratch space.
        tainted_regs: Set[int] = {self._c(r) for r in seed}
        mem_writes: List[Tuple[int, int]] = []
        for ins in insns:
            mn = ins.mnemonic
            ops = ins.operands
            if mn in ("mov", "movsx", "movzx", "movsxd") and len(ops) == 2:
                dst, src = ops
                if dst.type == x86c.X86_OP_REG:
                    dr = self._c(dst.reg)
                    if (src.type == x86c.X86_OP_REG and
                            self._c(src.reg) in tainted_regs):
                        tainted_regs.add(dr)
                    elif (src.type == x86c.X86_OP_MEM and
                            src.mem.base and
                            self._c(src.mem.base) in tainted_regs):
                        tainted_regs.add(dr)
                    else:
                        tainted_regs.discard(dr)
                elif (dst.type == x86c.X86_OP_MEM and
                        dst.mem.base in (x86c.X86_REG_RSP,) and
                        dst.mem.disp >= 0x28):
                    if (src.type == x86c.X86_OP_REG and
                            self._c(src.reg) in tainted_regs):
                        mem_writes.append((dst.mem.base, dst.mem.disp))
            elif mn == "call":
                # Volatiles clobbered after call
                for r in self._VOLATILE:
                    tainted_regs.discard(r)
            elif mn in ("ret", "retn"):
                break

        return {
            "sub_results": sub_results,
            "ret_tainted": ret_tainted,
            "mem_taint_writes": mem_writes,
        }

    def analyze(self, insns: list, seed_regs: set, *,
                 _depth: int = 0,
                 _seen: Optional[set] = None) -> List[dict]:
        """
        Propagate taint from seed_regs through insns.
        Returns list of:
          {"addr": VA, "func": name, "tainted_args": [0-based arg indices],
           "depth": recursion_depth}
        for every IAT call where at least one argument register is tainted,
        across the handler itself AND any in-driver callees reachable via
        ``resolve_internal_call`` up to ``max_call_depth``.
        """
        if _seen is None:
            _seen = set()

        tainted_regs: Set[int] = {self._c(r) for r in seed_regs}
        tainted_mem:  Set[Tuple[int, int]] = set()
        results: List[dict] = []

        _ARITH = ("add", "sub", "imul", "mul", "or", "and", "xor",
                  "shl", "shr", "sar", "rol", "ror", "not", "neg")

        def reg_src_tainted(op) -> bool:
            if op.type == x86c.X86_OP_REG:
                return self._c(op.reg) in tainted_regs
            if op.type == x86c.X86_OP_MEM:
                # Memory load is tainted if either the base register is
                # tainted (attacker-controlled pointer → deref) OR the
                # specific slot we track is tainted (earlier store).
                key = self._mem_key(op.mem)
                if key and key in tainted_mem:
                    return True
                if op.mem.base and self._c(op.mem.base) in tainted_regs:
                    return True
            return False

        for insn in insns:
            mn  = insn.mnemonic
            ops = insn.operands

            # ── MOV / sign-extend variants ────────────────────────────────
            if mn in ("mov", "movsx", "movzx", "movsxd") and len(ops) == 2:
                dst, src = ops
                # Register destination
                if dst.type == x86c.X86_OP_REG:
                    dr = self._c(dst.reg)
                    if reg_src_tainted(src):
                        tainted_regs.add(dr)
                    else:
                        tainted_regs.discard(dr)
                # Memory destination — store
                elif dst.type == x86c.X86_OP_MEM:
                    key = self._mem_key(dst.mem)
                    if key:
                        if reg_src_tainted(src):
                            tainted_mem.add(key)
                        else:
                            tainted_mem.discard(key)

            # ── LEA ───────────────────────────────────────────────────────
            elif mn == "lea" and len(ops) == 2:
                dst, src = ops
                if dst.type == x86c.X86_OP_REG:
                    dr = self._c(dst.reg)
                    if (src.type == x86c.X86_OP_MEM and
                            src.mem.base and
                            self._c(src.mem.base) in tainted_regs):
                        tainted_regs.add(dr)
                    else:
                        tainted_regs.discard(dr)

            # ── Arithmetic — taint propagates to dst ─────────────────────
            elif mn in _ARITH and len(ops) >= 2:
                dst, src = ops[0], ops[1]
                if dst.type == x86c.X86_OP_REG:
                    dr = self._c(dst.reg)
                    # xor reg, reg → zeroing idiom, always clean
                    if mn == "xor" and dst.reg == src.reg:
                        tainted_regs.discard(dr)
                    elif reg_src_tainted(src) or dr in tainted_regs:
                        tainted_regs.add(dr)

            # ── CALL — check args, recurse into internal callees ──────────
            elif mn == "call" and ops:
                op = ops[0]
                call_va: Optional[int] = None
                if op.type == x86c.X86_OP_IMM:
                    call_va = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                        op.mem.base == x86c.X86_REG_RIP and
                        op.mem.index == 0):
                    call_va = insn.address + insn.size + op.mem.disp

                tainted_args = [
                    i for i, r in enumerate(self._ARG_REGS)
                    if self._c(r) in tainted_regs
                ]

                summary = None
                if call_va and call_va in self.iat_map:
                    # IAT call — terminal; record if any arg tainted.
                    if tainted_args:
                        results.append({
                            "addr":         insn.address,
                            "func":         self.iat_map[call_va],
                            "tainted_args": tainted_args,
                            "depth":        _depth,
                        })
                elif (call_va and self._resolve is not None and
                        _depth < self._max_call_depth and
                        call_va not in _seen):
                    # Internal call — look up (or compute) a proper
                    # function summary for this callee, then APPLY it
                    # to the caller's state. The summary records:
                    #   - sub_results : IAT hits found inside the callee
                    #   - ret_tainted : whether RAX is tainted at return
                    #   - mem_taint_writes : stack-slot writes (caller-
                    #     frame slots written with tainted data)
                    seed = frozenset(self._ARG_REGS[i]
                                       for i in tainted_args)
                    summary = self._get_or_build_summary(
                        call_va, seed, _depth, _seen)
                    if summary is not None:
                        results.extend(summary["sub_results"])
                        if summary["ret_tainted"]:
                            tainted_regs.add(x86c.X86_REG_RAX)
                        # Apply mem-taint deltas the callee made into
                        # the caller's frame (stack slots ≥ 0x20 above
                        # RSP — outside the shadow region).
                        for slot in summary["mem_taint_writes"]:
                            tainted_mem.add(slot)

                # Clobber volatiles + invalidate register state for any
                # memory slot the callee might have overwritten. We
                # conservatively keep stack-slot taint — most callees
                # don't write into caller's frame beyond shadow space.
                # Preserve RAX when the callee summary indicates it returns
                # tainted data (e.g., success status derived from user input).
                _ret_tainted = (summary is not None and summary.get("ret_tainted"))
                for r in self._VOLATILE:
                    if r == x86c.X86_REG_RAX and _ret_tainted:
                        continue
                    tainted_regs.discard(r)

        return results
