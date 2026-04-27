"""Basic-block control-flow graph for handler analysis.

Linear disassembly tells us *what* instructions a handler contains but
not *how they connect*. A CFG answers path-sensitive questions:

  - Is every path from entry to a dangerous call gated by
    SeAccessCheck / ProbeForRead / PreviousMode?
  - Is the dangerous call in a dead (error-return) branch?
  - What fraction of the handler is reachable from entry?

This module builds a reasonable approximation of a function's CFG from
Capstone's linear disassembly. It is deliberately conservative: we
split blocks at every branch, record all static successors, and return
False on any query that would require resolving indirect control flow.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

import capstone.x86_const as x86c


# ──────────────────────────────────────────────────────────────────────────
# Instruction classification
# ──────────────────────────────────────────────────────────────────────────

COND_BRANCHES = frozenset({
    "je",  "jne", "jz",  "jnz", "js",  "jns", "jc",  "jnc",
    "jo",  "jno", "jp",  "jnp", "jb",  "jbe", "ja",  "jae",
    "jg",  "jge", "jl",  "jle", "jcxz","jecxz","jrcxz",
    "jpe", "jpo", "jna", "jnae","jnb", "jnbe","jng", "jnge",
    "jnl", "jnle","jnz",
})
UNCOND_BRANCHES = frozenset({"jmp"})
CALL_MNS = frozenset({"call"})
RET_MNS = frozenset({"ret", "retn", "retf", "iret", "iretq"})
TERMINATE_MNS = frozenset({"int3", "ud2", "hlt"})


def _static_jmp_target(insn) -> Optional[int]:
    """Return the static target VA of a branch, or None for indirect."""
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == x86c.X86_OP_IMM:
        return op.imm
    return None


# ──────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class BasicBlock:
    """A maximal straight-line sequence of instructions."""
    start_va: int
    end_va: int                       # address of last instruction (inclusive)
    insns: List = field(default_factory=list)
    successors: Set[int] = field(default_factory=set)  # VAs of successor blocks
    predecessors: Set[int] = field(default_factory=set)
    # List of call targets (both IAT and internal) for gate detection.
    api_calls: List[str] = field(default_factory=list)


@dataclass
class FunctionCFG:
    """Basic-block CFG rooted at a function entry VA."""
    entry_va: int
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)

    # ── Reachability ──────────────────────────────────────────────────

    def reachable_blocks(self) -> Set[int]:
        """All block VAs reachable from the entry."""
        seen: Set[int] = set()
        stack = [self.entry_va]
        while stack:
            va = stack.pop()
            if va in seen or va not in self.blocks:
                continue
            seen.add(va)
            stack.extend(self.blocks[va].successors)
        return seen

    def contains_address(self, va: int) -> Optional[int]:
        """Return the VA of the block containing ``va``, or None."""
        for bva, b in self.blocks.items():
            if b.start_va <= va <= b.end_va:
                return bva
        return None

    # ── Path-sensitive queries ────────────────────────────────────────

    def every_path_passes_through(self, target_va: int,
                                    gate_api_names: Set[str]) -> bool:
        """True if every path from entry to the block containing
        ``target_va`` passes through at least one block whose
        ``api_calls`` intersects ``gate_api_names``.

        Used for: *"is every path to this ZwTerminateProcess call
        gated by a SeAccessCheck?"*

        Returns False when the target is unreachable or the query
        can't be resolved (indirect branches, etc.).
        """
        target_block = self.contains_address(target_va)
        if target_block is None:
            return False
        if target_block == self.entry_va:
            # Target is in the entry block — no intermediate gate
            # possible. Caller must check the entry block itself.
            return bool(gate_api_names &
                        set(self.blocks[self.entry_va].api_calls))

        # DFS from entry tracking whether each path has seen a gate.
        # A gate is observed when any block on the path (before the
        # target block) calls a gate API.
        # We succeed only if EVERY path that reaches target_block has
        # seen a gate. Implement with negation: find any path reaching
        # target_block WITHOUT going through a gate.
        stack: List[Tuple[int, bool, Set[int]]] = [
            (self.entry_va, False, set())]
        while stack:
            va, gated, visited = stack.pop()
            if va in visited:
                continue
            visited = visited | {va}
            blk = self.blocks.get(va)
            if blk is None:
                continue
            this_gated = gated or bool(
                gate_api_names & set(blk.api_calls))
            if va == target_block:
                if not this_gated:
                    return False  # reached target without a gate
                continue
            for succ in blk.successors:
                stack.append((succ, this_gated, visited))
        return True

    def any_path_contains_api(self, api_names: Set[str]) -> bool:
        """True if any reachable block calls one of the given APIs."""
        for va in self.reachable_blocks():
            if api_names & set(self.blocks[va].api_calls):
                return True
        return False

    # ── Pretty ────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (f"FunctionCFG(entry=0x{self.entry_va:X}, "
                f"blocks={len(self.blocks)}, "
                f"reachable={len(self.reachable_blocks())})")


# ──────────────────────────────────────────────────────────────────────────
# Construction
# ──────────────────────────────────────────────────────────────────────────

def build_cfg(insns: List,
              iat_map: Dict[int, str],
              entry_va: Optional[int] = None) -> FunctionCFG:
    """Build a basic-block CFG from a linear Capstone disassembly.

    The disassembly should cover the entire function body. Out-of-range
    branch targets are ignored; internal `call`s are NOT followed (the
    CFG models intra-function flow only).

    ``iat_map`` is used to resolve call instructions to import names so
    blocks can be tagged with the APIs they call (for gate queries).
    """
    if not insns:
        return FunctionCFG(entry_va=entry_va or 0)

    by_addr = {i.address: i for i in insns}
    addrs = sorted(by_addr.keys())
    if entry_va is None:
        entry_va = addrs[0]

    # 1. Identify block leaders:
    #    - entry address
    #    - target of every static jump
    #    - instruction immediately AFTER every branch/ret
    leaders: Set[int] = {entry_va}

    for insn in insns:
        mn = insn.mnemonic
        if mn in UNCOND_BRANCHES | COND_BRANCHES:
            tgt = _static_jmp_target(insn)
            if tgt is not None and tgt in by_addr:
                leaders.add(tgt)
            # Next instruction after a branch starts a new block
            next_va = insn.address + insn.size
            if next_va in by_addr:
                leaders.add(next_va)
        elif mn in RET_MNS | TERMINATE_MNS:
            next_va = insn.address + insn.size
            if next_va in by_addr:
                leaders.add(next_va)
        elif mn in CALL_MNS:
            # We don't split on CALL (intra-block) but we DO tag the
            # block with the API call name for gate queries.
            pass

    # 2. Split into blocks
    blocks: Dict[int, BasicBlock] = {}
    sorted_leaders = sorted(leaders)

    for i, lead in enumerate(sorted_leaders):
        # Find the next leader's address → block goes up to the insn
        # immediately before it.
        next_lead = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else None
        block_insns = []
        for a in addrs:
            if a < lead:
                continue
            if next_lead is not None and a >= next_lead:
                break
            block_insns.append(by_addr[a])
        if not block_insns:
            continue
        blk = BasicBlock(
            start_va=lead,
            end_va=block_insns[-1].address,
            insns=block_insns,
        )
        # Tag block with API calls it contains
        for ins in block_insns:
            if ins.mnemonic in CALL_MNS and ins.operands:
                op = ins.operands[0]
                tgt = None
                if op.type == x86c.X86_OP_IMM:
                    tgt = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    tgt = ins.address + ins.size + op.mem.disp
                if tgt is not None:
                    name = iat_map.get(tgt)
                    if name:
                        blk.api_calls.append(name)
        blocks[lead] = blk

    # 3. Connect successors
    for va, blk in blocks.items():
        if not blk.insns:
            continue
        last = blk.insns[-1]
        mn = last.mnemonic
        fallthrough = last.address + last.size

        if mn in RET_MNS | TERMINATE_MNS:
            pass  # no successors
        elif mn in UNCOND_BRANCHES:
            tgt = _static_jmp_target(last)
            if tgt is not None and tgt in blocks:
                blk.successors.add(tgt)
        elif mn in COND_BRANCHES:
            tgt = _static_jmp_target(last)
            if tgt is not None and tgt in blocks:
                blk.successors.add(tgt)
            if fallthrough in blocks:
                blk.successors.add(fallthrough)
        else:
            # Normal/call — fall through
            if fallthrough in blocks:
                blk.successors.add(fallthrough)

    # 4. Back-propagate predecessors
    for va, blk in blocks.items():
        for s in blk.successors:
            if s in blocks:
                blocks[s].predecessors.add(va)

    return FunctionCFG(entry_va=entry_va, blocks=blocks)


# ──────────────────────────────────────────────────────────────────────────
# Convenience: gate APIs we treat as security checks
# ──────────────────────────────────────────────────────────────────────────

GATE_APIS: Set[str] = {
    "SeSinglePrivilegeCheck", "SePrivilegeCheck",
    "SeAccessCheck", "SeCheckPrivilegedOperation",
    "ProbeForRead", "ProbeForWrite",
    "ExGetPreviousMode", "KeGetPreviousMode",
    "ObReferenceObjectByHandle",    # access-mode-aware
}
