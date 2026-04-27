"""Cached function summaries for interprocedural taint.

A summary describes, for one function, what happens to taint when its
input register arguments are tainted:

  - which IAT calls it makes with tainted args (and which arg indices)
  - whether RAX is tainted at return
  - which stack/memory slots in the caller's frame become tainted

Replaces the inlined-callee approach: instead of disassembling and
re-tainting a helper every time it's called, we compute its summary
once (per (callee_va, tainted-arg-set) input shape), cache it, and
apply the summary at every call site.

Built lazily — a summary is computed the first time it's needed.
The TaintTracker queries this cache via a callback.

Notes:
  - We over-approximate by always summarizing under "all args tainted"
    when the caller's seed is non-empty. Cheaper than computing N
    summaries per arity, and the IAT-hit list is what actually matters
    downstream (per-hit ``tainted_args`` precision is preserved).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple


@dataclass
class FunctionSummary:
    """Effect of calling a function with all 4 arg regs tainted."""
    va: int
    iat_hits: List[dict] = field(default_factory=list)  # forward-taint output
    ret_tainted: bool = False
    # Reserved for future use — memory slots tainted on return.
    mem_taint_writes: List[Tuple[int, int]] = field(default_factory=list)


class SummaryCache:
    """Lazy per-function summary cache.

    Construct with a ``compute(va) -> FunctionSummary`` callback that
    knows how to actually run taint over a function. The cache de-dupes
    repeated calls, breaks recursion via a tombstone, and exposes the
    per-function result by VA.
    """

    _SENTINEL = object()  # marks "currently being computed" to break recursion

    def __init__(self,
                 compute: Callable[[int], Optional[FunctionSummary]]):
        self._compute = compute
        self._cache: Dict[int, object] = {}

    def get(self, va: int) -> Optional[FunctionSummary]:
        cached = self._cache.get(va, None)
        if cached is self._SENTINEL:
            # Recursive call back into a function we're already
            # summarizing. Return an empty summary to break the cycle.
            return FunctionSummary(va=va)
        if cached is not None:
            return cached  # type: ignore[return-value]
        # Mark as in-flight, compute, store.
        self._cache[va] = self._SENTINEL
        try:
            summary = self._compute(va)
        except Exception:
            summary = None
        if summary is None:
            summary = FunctionSummary(va=va)
        self._cache[va] = summary
        return summary

    # Diagnostic / introspection
    def all(self) -> Dict[int, FunctionSummary]:
        return {k: v for k, v in self._cache.items()
                if v is not self._SENTINEL and v is not None}

    def __len__(self) -> int:
        return len([v for v in self._cache.values()
                    if v is not self._SENTINEL])
