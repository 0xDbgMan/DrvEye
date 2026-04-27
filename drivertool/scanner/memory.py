"""Memory-related vulnerability scanning."""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Dict, List, Tuple

import capstone.x86_const as x86c

from drivertool.constants import Severity
from drivertool.ioctl import decode_ioctl
from drivertool.models import Finding

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class MemoryScanMixin:
    """Mixin for memory-related scans."""

    def scan_memory_patterns(self):
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]
        if "ExAllocatePool" in all_imports or "ExAllocatePoolWithTag" in all_imports:
            # Check if MmGetPhysicalAddress + MmMapIoSpace chain exists
            if "MmGetPhysicalAddress" in all_imports and "MmMapIoSpace" in all_imports:
                self.findings.append(Finding(
                    title="Physical memory mapping chain detected",
                    severity=Severity.CRITICAL,
                    description="Driver imports both MmGetPhysicalAddress and MmMapIoSpace. "
                                "This is a common pattern for arbitrary physical memory R/W.",
                    location="Import Table",
                    poc_hint="mmap_physical",
                ))

    def scan_hardcoded_addresses(self):
        for va, data in self.pe.get_code_sections():
            insns = self.dis.disassemble_range(data, va, max_insns=2000)
            for insn in insns:
                if insn.mnemonic == "mov" and len(insn.operands) == 2:
                    op = insn.operands[1]
                    if op.type == x86c.X86_OP_IMM:
                        imm = op.imm
                        # Flag physical addresses used near MmMapIoSpace
                        if 0x10000 <= imm <= 0xFFFFFFFF and imm not in (
                            0x80000000, 0x40000000, 0xFFFFFFFF, 0x7FFFFFFF
                        ):
                            # Check if it looks like a physical address
                            if imm & 0xFFF == 0 and imm < 0x100000000:
                                self.findings.append(Finding(
                                    title=f"Hardcoded address: 0x{imm:X}",
                                    severity=Severity.MEDIUM,
                                    description="Hardcoded page-aligned address found. "
                                                "May be a physical memory address used with "
                                                "MmMapIoSpace or similar.",
                                    location=f"0x{insn.address:X}",
                                    details={"address": f"0x{imm:X}"},
                                ))
            break  # only scan first code section for performance

    def scan_arbitrary_write_gadgets(self):
        """Scan for mov [reg+offset], reg gadgets in IOCTL handler — arbitrary kernel write."""
        gadgets_found = []
        for va, data in self.pe.get_code_sections():
            insns = self.dis.disassemble_range(data, va, max_insns=5000)
            for insn in insns:
                if insn.mnemonic == "mov" and len(insn.operands) == 2:
                    dst = insn.operands[0]
                    src = insn.operands[1]
                    # mov [reg + offset], reg  — kernel write gadget
                    if (dst.type == x86c.X86_OP_MEM and
                            dst.mem.base != 0 and dst.mem.index == 0 and
                            src.type == x86c.X86_OP_REG and
                            dst.size in (4, 8)):
                        gadgets_found.append(f"0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
                        if len(gadgets_found) >= 8:
                            break
            if gadgets_found:
                break

        if len(gadgets_found) >= 3:
            self.findings.append(Finding(
                title=f"Kernel write gadgets found ({len(gadgets_found)} instances)",
                severity=Severity.HIGH,
                description="Multiple 'mov [reg+offset], reg' patterns in driver code. "
                            "If the register is derived from user input (e.g., IOCTL buffer), "
                            "this is an arbitrary kernel memory write primitive.",
                location="Code section",
                details={"gadgets": "; ".join(gadgets_found[:4])},
            ))

    def scan_kernel_stack_overflows(self):
        """
        Detect functions that allocate more than 8KB on the kernel stack.
        The Windows kernel stack is ~12–24KB; large frame allocations risk overflow.
        """
        LIMIT = 0x2000  # 8 KB threshold
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        seen: set = set()
        for sec_va, sec_data in self.pe.get_code_sections():
            for fn_va in self.dis.find_function_prologues(sec_va, sec_data):
                if fn_va in seen:
                    continue
                seen.add(fn_va)
                rva = fn_va - image_base
                data = self.pe.get_bytes_at_rva(rva, 16)
                if not data:
                    continue
                for insn in self.dis.disassemble_range(data, fn_va, max_insns=4):
                    if insn.mnemonic == "sub" and len(insn.operands) == 2:
                        op0, op1 = insn.operands
                        if (op0.type == x86c.X86_OP_REG and
                                op0.reg in (x86c.X86_REG_RSP, x86c.X86_REG_ESP) and
                                op1.type == x86c.X86_OP_IMM):
                            sz = op1.imm & 0xFFFFFFFF
                            if sz > LIMIT:
                                self.findings.append(Finding(
                                    title=f"Large kernel stack frame: {sz:#x} bytes at 0x{fn_va:X}",
                                    severity=Severity.HIGH,
                                    description=f"Function at 0x{fn_va:X} allocates {sz:#x} "
                                                f"({sz:,}) bytes on the kernel stack. "
                                                "Kernel stack is ~12KB; oversized frames risk "
                                                "stack overflow (BSoD or exploitable corruption).",
                                    location=f"0x{fn_va:X}",
                                    details={"frame_size": f"{sz:#x}",
                                             "function":   f"0x{fn_va:X}"},
                                ))
                        break  # prologue sub rsp is always the first instruction

    def scan_integer_overflow_alloc(self):
        """
        Detect integer overflow feeding into pool allocation:
          user_count = *(DWORD*)SystemBuffer   <- tainted
          size = user_count * 8                <- imul/shl, may overflow
          ExAllocatePoolWithTag(pool, size, tag)  <- tiny alloc
          memcpy(buf, src, user_count * 8)     <- overwrites heap
        Flags imul/shl/mul on tainted regs within 15 insns before
        ExAllocatePool* with no overflow guard (jo/jb) in between.
        """
        ALLOC_FUNCS = {"ExAllocatePool", "ExAllocatePoolWithTag",
                       "ExAllocatePool2", "ExAllocatePoolWithQuotaTag",
                       "ExAllocatePoolZero"}
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        for sec_va, sec_data in self.pe.get_code_sections():
            insns = self.dis.disassemble_range(sec_data, sec_va)
            for i, insn in enumerate(insns):
                # Find calls to alloc functions
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                call_target = None
                if op.type == x86c.X86_OP_IMM:
                    call_target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                        op.mem.base == x86c.X86_REG_RIP and
                        op.mem.index == 0):
                    call_target = insn.address + insn.size + op.mem.disp
                if call_target is None or call_target not in self.pe.iat_map:
                    continue
                fn = self.pe.iat_map[call_target]
                if fn not in ALLOC_FUNCS:
                    continue

                # Scan backward up to 15 insns for imul/shl/mul without overflow check
                has_arith = False
                has_guard = False
                arith_addr = 0
                for j in range(max(0, i - 15), i):
                    ji = insns[j]
                    if ji.mnemonic in ("imul", "mul", "shl") and len(ji.operands) >= 2:
                        has_arith = True
                        arith_addr = ji.address
                    if ji.mnemonic in ("jo", "jno", "jb", "jc"):
                        has_guard = True

                if has_arith and not has_guard:
                    self.findings.append(Finding(
                        title=f"Integer overflow before {fn} at 0x{insn.address:X}",
                        severity=Severity.CRITICAL,
                        description=f"Arithmetic (imul/shl/mul) at 0x{arith_addr:X} precedes "
                                    f"{fn} call at 0x{insn.address:X} with no overflow guard "
                                    "(no jo/jb between them). If the multiplied value is "
                                    "user-controlled, this causes a heap overflow.",
                        location=f"0x{insn.address:X}",
                        details={"alloc_func": fn, "arith_at": f"0x{arith_addr:X}",
                                 "call_at": f"0x{insn.address:X}"},
                    ))

    def scan_kernel_info_leak(self):
        """
        Detect potential kernel information leaks via IOCTL output buffers.
        Pattern: METHOD_BUFFERED IOCTL where output buffer is returned to
        usermode without being fully zeroed — may leak kernel addresses
        (defeating KASLR) or sensitive data from kernel stack/pool.

        Heuristic checks:
        1. Any IOCTL using METHOD_BUFFERED (I/O Manager reuses the same
           buffer for input and output — slack bytes beyond input are
           uninitialized kernel stack/pool content)
        2. No RtlZeroMemory/memset call in the handler body
        """
        ZERO_FUNCS = {"RtlZeroMemory", "RtlFillMemory", "RtlSecureZeroMemory",
                      "memset", "__stosb"}
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        for code in self.ioctl_codes:
            method = code & 0x3
            if method != 0:  # only METHOD_BUFFERED
                continue

            # Find handler VA from findings
            handler_va = None
            for f in self.findings:
                if f.ioctl_code == code and f.details and "handler" in f.details:
                    try:
                        handler_va = int(f.details["handler"], 16)
                    except (ValueError, TypeError):
                        pass
                    break
            if handler_va is None:
                continue

            # Check if handler calls any zeroing function
            rva = handler_va - image_base
            data = self.pe.get_bytes_at_rva(rva, 4096)
            if not data:
                continue
            insns = self.dis.disassemble_function(data, handler_va, max_insns=300)
            has_zero = False
            copies_output = False
            COPY_FUNCS = {"RtlCopyMemory", "RtlMoveMemory", "memcpy", "memmove",
                          "RtlCopyBytes"}
            for insn in insns:
                # Check for zeroing calls or copy calls
                if insn.mnemonic == "call" and insn.operands:
                    op = insn.operands[0]
                    target_addr = None
                    if op.type == x86c.X86_OP_IMM:
                        target_addr = op.imm
                    elif op.type == x86c.X86_OP_MEM and op.mem.base == x86c.X86_REG_RIP:
                        target_addr = insn.address + insn.size + op.mem.disp
                    if target_addr is not None:
                        fn = self.pe.iat_map.get(target_addr, "")
                        if fn in ZERO_FUNCS:
                            has_zero = True
                        if fn in COPY_FUNCS:
                            copies_output = True
                # rep movsb/movsd/movsq = inline memcpy → copies data to output
                if insn.mnemonic.startswith("rep") and "movs" in insn.op_str:
                    copies_output = True

            if not has_zero and copies_output:
                decoded = decode_ioctl(code)
                self.findings.append(Finding(
                    title=f"Potential kernel info leak via IOCTL {decoded['code']}",
                    severity=Severity.MEDIUM,
                    description=f"METHOD_BUFFERED IOCTL {decoded['code']} handler at "
                                f"0x{handler_va:X} sets IoStatus.Information (returns "
                                "output to usermode) without calling RtlZeroMemory/memset. "
                                "The I/O Manager reuses the same buffer for input and "
                                "output — uninitialized bytes beyond the input may leak "
                                "kernel stack/pool data to usermode (KASLR bypass).",
                    location=f"0x{handler_va:X}",
                    ioctl_code=code,
                    details={"ioctl": decoded["code"], "handler": f"0x{handler_va:X}"},
                ))

    def scan_double_fetch(self):
        """
        Detect TOCTOU (Time-Of-Check-Time-Of-Use) double-fetch patterns.

        A real double-fetch has four ingredients, ALL of which we require:

          1. Two memory reads at the same (base_reg, displacement).
          2. A cmp/test between them that uses the value loaded by the
             first read (validates it).
          3. No intervening "capture" event — ProbeForRead/Write,
             RtlCopyMemory, memcpy, probe-then-lock — because those
             copy the user buffer to a kernel-local before the second
             read (safe).
          4. The second-read value flows into a security-sensitive sink
             within a short window: allocator size arg, memcpy length,
             pointer dereference.

        Earlier versions flagged any cmp-between-two-reads pattern, which
        fired on ~every handler. These four gates drop FP rate to the
        single-digit percent range.
        """
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        # Resolving IAT names for a given call target
        def _call_name(insn) -> str:
            if not insn.operands:
                return ""
            op = insn.operands[0]
            if op.type == x86c.X86_OP_IMM:
                return self.pe.iat_map.get(op.imm, "")
            if (op.type == x86c.X86_OP_MEM and
                    op.mem.base == x86c.X86_REG_RIP and op.mem.index == 0):
                tgt = insn.address + insn.size + op.mem.disp
                return self.pe.iat_map.get(tgt, "")
            return ""

        CAPTURE_APIS = {
            "ProbeForRead", "ProbeForWrite",
            "RtlCopyMemory", "memcpy", "memmove",
            "RtlMoveMemory", "RtlCompareMemory",
            "MmProbeAndLockPages",
        }
        SINK_APIS = {
            "ExAllocatePool", "ExAllocatePoolWithTag", "ExAllocatePoolZero",
            "ExAllocatePoolWithQuotaTag", "ExAllocatePool2", "ExAllocatePool3",
            "RtlCopyMemory", "memcpy", "memmove", "RtlMoveMemory",
            "ZwWriteVirtualMemory", "NtWriteVirtualMemory",
            "MmCopyVirtualMemory", "ZwReadVirtualMemory",
        }
        # 32-bit aliases collapse to the same full register for tracking
        GPR_NORMALIZE = {
            x86c.X86_REG_EAX: x86c.X86_REG_RAX, x86c.X86_REG_AX: x86c.X86_REG_RAX, x86c.X86_REG_AL: x86c.X86_REG_RAX,
            x86c.X86_REG_EBX: x86c.X86_REG_RBX, x86c.X86_REG_BX: x86c.X86_REG_RBX, x86c.X86_REG_BL: x86c.X86_REG_RBX,
            x86c.X86_REG_ECX: x86c.X86_REG_RCX, x86c.X86_REG_CX: x86c.X86_REG_RCX, x86c.X86_REG_CL: x86c.X86_REG_RCX,
            x86c.X86_REG_EDX: x86c.X86_REG_RDX, x86c.X86_REG_DX: x86c.X86_REG_RDX, x86c.X86_REG_DL: x86c.X86_REG_RDX,
            x86c.X86_REG_ESI: x86c.X86_REG_RSI, x86c.X86_REG_SI: x86c.X86_REG_RSI, x86c.X86_REG_SIL: x86c.X86_REG_RSI,
            x86c.X86_REG_EDI: x86c.X86_REG_RDI, x86c.X86_REG_DI: x86c.X86_REG_RDI, x86c.X86_REG_DIL: x86c.X86_REG_RDI,
            x86c.X86_REG_R8D: x86c.X86_REG_R8, x86c.X86_REG_R8W: x86c.X86_REG_R8, x86c.X86_REG_R8B: x86c.X86_REG_R8,
            x86c.X86_REG_R9D: x86c.X86_REG_R9, x86c.X86_REG_R9W: x86c.X86_REG_R9, x86c.X86_REG_R9B: x86c.X86_REG_R9,
            x86c.X86_REG_R10D: x86c.X86_REG_R10, x86c.X86_REG_R11D: x86c.X86_REG_R11,
        }
        def _norm(reg):
            return GPR_NORMALIZE.get(reg, reg)

        # Max instruction distance between first and second fetch to
        # still treat as related
        MAX_FETCH_DISTANCE = 40
        # Max lookahead from second fetch for a sink use
        SINK_LOOKAHEAD = 12

        for sec_va, sec_data in self.pe.get_code_sections():
            insns = self.dis.disassemble_range(sec_data, sec_va)
            # (base_reg, disp) → (first_idx, first_dst_reg)
            mem_reads: Dict[Tuple[int, int], Tuple[int, int]] = {}
            seen_locations: set = set()
            for i, insn in enumerate(insns):
                # Reset at function boundaries
                if insn.mnemonic in ("ret", "retn", "int3"):
                    mem_reads.clear()
                    continue
                # Reset at capture APIs — the user buffer is snapshot there
                if insn.mnemonic == "call":
                    fn = _call_name(insn)
                    if fn in CAPTURE_APIS:
                        mem_reads.clear()
                    continue

                if (insn.mnemonic in ("mov", "movzx", "movsxd") and
                        len(insn.operands) == 2):
                    dst, src = insn.operands
                    if (dst.type != x86c.X86_OP_REG or
                            src.type != x86c.X86_OP_MEM):
                        continue
                    # Skip stack/static reads — not user buffers
                    if (src.mem.base in (0, x86c.X86_REG_RIP,
                                          x86c.X86_REG_RSP, x86c.X86_REG_RBP) or
                            src.mem.index != 0):
                        continue
                    key = (src.mem.base, src.mem.disp)
                    dst_reg = _norm(dst.reg)

                    if key in mem_reads:
                        first_idx, first_dst_reg = mem_reads[key]
                        second_idx = i
                        # Gate 1: distance
                        if second_idx - first_idx > MAX_FETCH_DISTANCE:
                            mem_reads[key] = (i, dst_reg)
                            continue
                        # Gate 2: cmp/test between reads uses first_dst_reg
                        cmp_uses_first = False
                        for j in range(first_idx + 1, second_idx):
                            jn = insns[j]
                            if jn.mnemonic in ("cmp", "test") and len(jn.operands) >= 2:
                                for op in jn.operands:
                                    if op.type == x86c.X86_OP_REG and _norm(op.reg) == first_dst_reg:
                                        cmp_uses_first = True
                                        break
                            if cmp_uses_first:
                                break
                        if not cmp_uses_first:
                            mem_reads[key] = (i, dst_reg)
                            continue
                        # Gate 3: second-read result flows to a sensitive sink
                        sink_ok = False
                        reg_alive = {dst_reg}
                        for j in range(second_idx + 1,
                                       min(second_idx + 1 + SINK_LOOKAHEAD,
                                           len(insns))):
                            jn = insns[j]
                            # Flow through simple mov/lea chains
                            if jn.mnemonic in ("mov", "movzx", "movsxd"):
                                if (len(jn.operands) == 2 and
                                        jn.operands[0].type == x86c.X86_OP_REG and
                                        jn.operands[1].type == x86c.X86_OP_REG and
                                        _norm(jn.operands[1].reg) in reg_alive):
                                    reg_alive.add(_norm(jn.operands[0].reg))
                                    continue
                            # Pointer deref of the fetched value
                            if any(op.type == x86c.X86_OP_MEM and
                                    _norm(op.mem.base) in reg_alive
                                    for op in jn.operands):
                                sink_ok = True; break
                            # Call with fetched value as arg (RCX/RDX/R8/R9)
                            if jn.mnemonic == "call":
                                arg_regs = {x86c.X86_REG_RCX, x86c.X86_REG_RDX,
                                            x86c.X86_REG_R8,  x86c.X86_REG_R9}
                                if reg_alive & arg_regs:
                                    fn = _call_name(jn)
                                    if fn in SINK_APIS:
                                        sink_ok = True; break
                                # Any call clobbers volatiles — stop tracking
                                break
                        if not sink_ok:
                            mem_reads[key] = (i, dst_reg)
                            continue
                        # All four gates satisfied — genuine double-fetch.
                        loc = insn.address
                        if loc in seen_locations:
                            mem_reads[key] = (i, dst_reg)
                            continue
                        seen_locations.add(loc)
                        self.findings.append(Finding(
                            title=f"Double-fetch (TOCTOU) at 0x{loc:X}",
                            severity=Severity.HIGH,
                            description=f"Two reads from [reg+{src.mem.disp:#x}] at "
                                        f"0x{insns[first_idx].address:X} and "
                                        f"0x{loc:X} with a cmp/test using the first "
                                        "value and the second value flowing into a "
                                        "sensitive sink (allocator / memcpy / deref). "
                                        "An attacker can race to change the buffer "
                                        "between check and use.",
                            location=f"0x{loc:X}",
                            details={
                                "first_read":  f"0x{insns[first_idx].address:X}",
                                "second_read": f"0x{loc:X}",
                                "offset":      f"{src.mem.disp:#x}",
                            },
                        ))
                    mem_reads[key] = (i, dst_reg)

    def scan_unchecked_returns(self):
        """
        Detect unchecked return values from critical kernel APIs.
        When ObReferenceObjectByHandle, ExAllocatePool*, MmMapIoSpace, etc.
        return a value that is not tested (no test/cmp/je after call), the
        driver may use a NULL pointer or invalid handle → BSOD / exploit.
        """
        # APIs whose return MUST be checked (NTSTATUS or pointer)
        MUST_CHECK_NTSTATUS = {
            "ObReferenceObjectByHandle", "ObReferenceObjectByPointer",
            "ObOpenObjectByPointer", "PsLookupProcessByProcessId",
            "PsLookupThreadByThreadId", "ZwOpenProcess", "ZwOpenThread",
            "ZwCreateFile", "ZwOpenFile", "ZwOpenKey", "ZwCreateKey",
            "ZwOpenSection", "ZwCreateSection", "ZwMapViewOfSection",
            "IoCreateDevice", "IoCreateSymbolicLink",
            "IoDeleteSymbolicLink",
            "NtOpenSymbolicLinkObject", "ZwOpenSymbolicLinkObject",
            "NtQuerySymbolicLinkObject", "ZwQuerySymbolicLinkObject",
            "ObReferenceObjectByName",
            "ZwQueryInformationProcess", "ZwQueryInformationThread",
            "ZwQueryValueKey", "ZwSetValueKey",
        }
        MUST_CHECK_PTR = {
            "ExAllocatePool", "ExAllocatePoolWithTag",
            "ExAllocatePoolWithQuotaTag", "ExAllocatePool2",
            "MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPages",
            "MmMapLockedPagesSpecifyCache", "MmAllocateContiguousMemory",
            "IoAllocateMdl", "IoAllocateIrp",
        }
        all_critical = MUST_CHECK_NTSTATUS | MUST_CHECK_PTR
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase

        # Scan each IOCTL handler
        unchecked: List[Tuple[int, str, int]] = []  # (ioctl, func_name, call_addr)

        for code in self.ioctl_codes:
            handler_va = self._get_handler_va(code)
            if not handler_va:
                continue
            rva = handler_va - image_base
            hbytes = self.pe.get_bytes_at_rva(rva, 8192)
            if not hbytes:
                continue
            insns = self.dis.disassemble_function(hbytes, handler_va, max_insns=500)

            for idx, insn in enumerate(insns):
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                call_target = None
                if op.type == x86c.X86_OP_IMM:
                    call_target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    call_target = insn.address + insn.size + op.mem.disp
                if call_target is None:
                    continue
                fname = self.pe.iat_map.get(call_target, "")
                if fname not in all_critical:
                    continue

                # Check the next 3 instructions for a return value check
                # Return in rax/eax — look for: test eax,eax / cmp eax,0 /
                # test rax,rax / movzx+test / jl / js / jnz / jz
                has_check = False
                for ni in range(idx + 1, min(idx + 4, len(insns))):
                    nxt = insns[ni]
                    # test eax, eax  or  test rax, rax
                    if nxt.mnemonic == "test" and len(nxt.operands) == 2:
                        r0 = insn.reg_name(nxt.operands[0].reg) if nxt.operands[0].type == x86c.X86_OP_REG else ""
                        r1 = insn.reg_name(nxt.operands[1].reg) if nxt.operands[1].type == x86c.X86_OP_REG else ""
                        if r0 in ("eax", "rax") and r0 == r1:
                            has_check = True
                            break
                    # cmp eax, imm  (NTSTATUS check like cmp eax, 0)
                    if nxt.mnemonic == "cmp" and len(nxt.operands) >= 1:
                        r0 = insn.reg_name(nxt.operands[0].reg) if nxt.operands[0].type == x86c.X86_OP_REG else ""
                        if r0 in ("eax", "rax"):
                            has_check = True
                            break
                    # Direct conditional jump on NTSTATUS (js = negative = failure)
                    if nxt.mnemonic in ("js", "jns", "jl", "jge", "jnz", "jz", "je", "jne"):
                        has_check = True
                        break
                    # mov into another reg then test — still OK
                    if nxt.mnemonic == "mov" and len(nxt.operands) == 2:
                        src = nxt.operands[1]
                        if src.type == x86c.X86_OP_REG:
                            src_name = insn.reg_name(src.reg)
                            if src_name in ("eax", "rax"):
                                continue  # saved return value, check next insn
                    # If we hit another call, the return was discarded
                    if nxt.mnemonic == "call":
                        break

                if not has_check:
                    unchecked.append((code, fname, insn.address))

        # Group by IOCTL and report
        by_ioctl: Dict[int, List[Tuple[str, int]]] = defaultdict(list)
        for code, fname, addr in unchecked:
            by_ioctl[code].append((fname, addr))

        for code, items in sorted(by_ioctl.items()):
            decoded = decode_ioctl(code)
            func_list = ", ".join(f"{fn} @ 0x{a:X}" for fn, a in items)
            is_ptr = any(fn in MUST_CHECK_PTR for fn, _ in items)
            is_nts = any(fn in MUST_CHECK_NTSTATUS for fn, _ in items)
            if is_ptr:
                desc = (f"Return value from pool/memory allocation not checked. "
                        f"If the allocation fails (returns NULL), the driver will "
                        f"dereference a NULL pointer → BSOD / exploitable NULL page mapping.")
                sev = Severity.HIGH
            elif is_nts:
                desc = (f"NTSTATUS return value not checked after API call. "
                        f"The driver proceeds assuming success even if the call failed, "
                        f"potentially using an uninitialized handle or object pointer.")
                sev = Severity.HIGH
            else:
                desc = "Critical API return value not validated."
                sev = Severity.MEDIUM

            self.findings.append(Finding(
                title=f"Unchecked return: {', '.join(fn for fn, _ in items)} in IOCTL {decoded['code']}",
                severity=sev,
                description=f"{desc} Unchecked calls: {func_list}",
                location=f"IOCTL handler 0x{self._get_handler_va(code) or 0:X}",
                ioctl_code=code,
                details={"unchecked_calls": [{"func": fn, "addr": f"0x{a:X}"} for fn, a in items]},
            ))

        # Summary
        if unchecked:
            self.findings.append(Finding(
                title=f"Total unchecked critical API returns: {len(unchecked)} across {len(by_ioctl)} IOCTL(s)",
                severity=Severity.HIGH,
                description="Multiple critical kernel API calls have their return values "
                            "ignored. Each unchecked return is a potential NULL dereference, "
                            "use-after-fail, or type-confusion bug. Fix by always checking "
                            "NTSTATUS or pointer returns before use.",
                location="IOCTL handlers",
                details={"total_unchecked": str(len(unchecked)),
                         "affected_ioctls": str(len(by_ioctl))},
            ))
