"""Taint analysis — tracks user input flow to dangerous sinks."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict, List, Optional

import capstone.x86_const as x86c

from drivertool.constants import DANGEROUS_IMPORTS, Severity
from drivertool.ioctl import HANDLER_PURPOSE_MAP
from drivertool.models import Finding
from drivertool.taint import TaintTracker

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class TaintScanMixin:
    """Mixin for taint analysis scans."""

    def scan_taint_user_input(self):
        """
        For each discovered IOCTL handler: seed rcx/rdx (IRP* and
        IO_STACK_LOCATION* — the two handler arguments) as tainted and
        propagate forward.  Report dangerous IAT calls whose first argument
        register is tainted (user-controlled data reaches a dangerous sink).
        """
        if not self.ioctl_codes:
            return

        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        tracker   = TaintTracker(self.pe.iat_map)
        # Seed: rcx (IRP*) and rdx (IO_STACK_LOCATION*) — both carry user data
        SEEDS = {x86c.X86_REG_RCX, x86c.X86_REG_RDX}

        # Build handler VA → IOCTL code(s) reverse map
        handler_to_codes: Dict[int, List[int]] = {}
        for code, purpose in self.ioctl_purposes.items():
            # We need the handler VA; find it via the findings
            for f in self.findings:
                if f.ioctl_code == code and "handler" in (f.details or {}):
                    try:
                        hva = int(f.details["handler"], 16)
                        handler_to_codes.setdefault(hva, []).append(code)
                    except (ValueError, TypeError):
                        pass

        # Deduplicate: analyze each unique handler VA once
        analyzed: set = set()
        for hva, codes in handler_to_codes.items():
            if hva in analyzed:
                continue
            analyzed.add(hva)
            rva  = hva - image_base
            data = self.pe.get_bytes_at_rva(rva, 4096)
            if not data:
                continue
            insns = self.dis.disassemble_function(data, hva, max_insns=300)
            hits  = tracker.analyze(insns, SEEDS)
            for hit in hits:
                fn   = hit["func"]
                args = hit["tainted_args"]
                if fn not in HANDLER_PURPOSE_MAP:
                    continue
                purpose_lbl, _ = HANDLER_PURPOSE_MAP[fn]
                arg_names = ["arg1(rcx)", "arg2(rdx)", "arg3(r8)", "arg4(r9)"]
                tainted_str = ", ".join(arg_names[a] for a in args if a < len(arg_names))
                ioctl_str = ", ".join(f"0x{c:08X}" for c in codes)
                self.findings.append(Finding(
                    title=(f"User-controlled data reaches {fn} "
                           f"({purpose_lbl}) via IOCTL {ioctl_str}"),
                    severity=Severity.CRITICAL,
                    description=f"Taint analysis: data derived from the IRP (user input) "
                                f"flows into {fn} as {tainted_str}. "
                                f"The {purpose_lbl} operation may be directly controllable "
                                "by an unprivileged caller.",
                    location=f"0x{hit['addr']:X}",
                    poc_hint="process_kill" if "kill" in purpose_lbl else
                            "process_kill" if purpose_lbl in ("process lookup", "process access") else "ioctl_generic",
                    ioctl_code=codes[0] if codes else None,
                    details={
                        "function":      fn,
                        "tainted_args":  tainted_str,
                        "call_address":  f"0x{hit['addr']:X}",
                        "handler":       f"0x{hva:X}",
                    },
                ))

    def scan_interprocedural_taint(self):
        """Full call-graph taint propagation from IOCTL input buffers.

        Uses the centralized TaintTracker (with interprocedural summaries)
        instead of the legacy hand-rolled propagation.
        """
        if not self.pe.is_64bit:
            return
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        def _resolve(va: int) -> Optional[list]:
            rva = va - image_base
            data = self.pe.get_bytes_at_rva(rva, 0x2000)
            if not data:
                return None
            return self.dis.disassemble_function(data, va, max_insns=2000)

        tracker = TaintTracker(
            self.pe.iat_map,
            resolve_internal_call=_resolve,
            max_call_depth=5,
        )

        # Seed: IRP in rdx, SystemBuffer at [rdx+0x18]
        SEEDS = {x86c.X86_REG_RDX}
        arg_reg_names = ["rcx", "rdx", "r8", "r9"]

        for code in self.ioctl_codes:
            handler_va = self._get_handler_va(code)
            if not handler_va:
                continue
            data = self.pe.get_bytes_at_rva(handler_va - image_base, 4096)
            if not data:
                continue
            insns = self.dis.disassemble_function(data, handler_va, max_insns=2000)
            hits = tracker.analyze(insns, SEEDS)
            for hit in hits:
                fn = hit["func"]
                tainted_args = hit["tainted_args"]
                tainted_str = ", ".join(
                    f"arg{i + 1}({arg_reg_names[i]})" for i in tainted_args
                    if i < len(arg_reg_names)
                )
                self.taint_paths.append({
                    "ioctl": code,
                    "sink": fn,
                    "sink_addr": hit["addr"],
                    "tainted_arg": tainted_str,
                    "depth": hit["depth"],
                })
                sev = DANGEROUS_IMPORTS.get(fn, (Severity.HIGH, "", ""))[0]
                self.findings.append(Finding(
                    title=f"Taint reaches {fn} via {tainted_str}",
                    severity=sev,
                    description=(
                        f"User-controlled IOCTL input (code 0x{code:08X}) "
                        f"reaches dangerous sink {fn} through {hit['depth']} "
                        f"call depth(s). Tainted arguments: {tainted_str}."
                    ),
                    location=f"0x{hit['addr']:X}",
                    details={
                        "sink": fn,
                        "tainted_arg": tainted_str,
                        "depth": str(hit["depth"]),
                    },
                    poc_hint=self._taint_poc_hint(fn),
                    ioctl_code=code,
                ))

    def _taint_poc_hint(self, sink: str) -> Optional[str]:
        """Map sink name to a PoC hint."""
        hints = {
            "MmMapIoSpace": "mmap_physical",
            "MmCopyVirtualMemory": "arbitrary_rw",
            "ZwWriteVirtualMemory": "arbitrary_rw",
            "__writemsr": "msr_readwrite",
            "ZwOpenProcess": "process_access",
            "ZwTerminateProcess": "process_kill",
        }
        return hints.get(sink)
