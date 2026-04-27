"""IOCTL Dispatch CFG Reconstructor — maps IOCTL codes to handler VAs."""
from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import capstone.x86_const as x86c

from drivertool.ioctl import is_valid_ioctl

if TYPE_CHECKING:
    from drivertool.pe_analyzer import PEAnalyzer
    from drivertool.disassembler import Disassembler


class IOCTLDispatchCFG:
    """
    Walks the control-flow graph of an IOCTL dispatch function and maps
    each IOCTL code to its handler VA.

    Handles four compiler patterns:
      SUB-chain  : sub eax, BASE; je handler_A; sub eax, DELTA; je handler_B
      CMP/JE     : cmp eax, IOCTL; je handler
      CMP/JNE    : cmp eax, IOCTL; jne skip; [inline handler at skip+1]
      JMP        : unconditional jump — follow, preserving accumulator
      Jump table : sub eax,BASE; [shr eax,2]; cmp eax,N; ja default;
                   lea rcx,[rip+table]; movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax
    """

    def __init__(self, pe: PEAnalyzer, dis: Disassembler):
        self.pe = pe
        self.dis = dis

    # ── Jump table helper ──────────────────────────────────────────────────

    def _try_read_jump_table(self, insns: list, cmp_idx: int,
                              count: int, sub_acc: Optional[int],
                              has_shr: bool, image_base: int
                              ) -> List[Tuple[int, int]]:
        """
        Called when we see `cmp reg, count` that looks like a bounds check.
        Scans ahead up to 10 instructions for:
            ja/jae  [bounds-failure jump — ignored]
            lea reg1, [rip+X]           <- table pointer
            movsxd/mov rax, [reg1+rax*4]
            add rax, reg1
            jmp rax                     <- indirect dispatch

        On success reads the jump table from PE data and returns
        [(ioctl_code, handler_va), ...] with default/error entries removed.

        IOCTL reconstruction:
          - base  = sub_acc (accumulated SUB value) or 0
          - If has_shr (shr eax,2 seen between sub and cmp):
                ioctl_i = base + i*4   (compiler divided index by 4)
          - Otherwise:
                ioctl_i = base + i     (raw normalized index)
            In the non-shr case many entries are "default"; they are
            filtered by removing the most-common handler VA.
        """
        table_va: Optional[int] = None
        base_va: Optional[int] = None
        byte_table_off: Optional[int] = None
        dword_table_off: Optional[int] = None
        found_jmp = False
        two_level = False

        window = insns[cmp_idx + 1 : min(cmp_idx + 16, len(insns))]
        for ji in window:
            if ji.mnemonic in ("ja", "jae", "movsxd", "mov", "add"):
                if ji.mnemonic in ("mov", "movsxd") and len(ji.operands) == 2:
                    src = ji.operands[1]
                    if (src.type == x86c.X86_OP_MEM and src.mem.scale == 4
                            and src.mem.disp != 0):
                        dword_table_off = src.mem.disp
                continue
            if ji.mnemonic == "movzx" and len(ji.operands) == 2:
                src = ji.operands[1]
                if (src.type == x86c.X86_OP_MEM and src.size == 1
                        and src.mem.disp != 0):
                    byte_table_off = src.mem.disp
                    two_level = True
                continue
            if ji.mnemonic == "lea" and len(ji.operands) == 2:
                src = ji.operands[1]
                if (src.type == x86c.X86_OP_MEM and
                        src.mem.base == x86c.X86_REG_RIP and
                        src.mem.index == 0):
                    resolved = ji.address + ji.size + src.mem.disp
                    if table_va is None:
                        table_va = resolved
                    base_va = resolved
                continue
            if ji.mnemonic == "jmp":
                found_jmp = True
                break
            break

        if not found_jmp or table_va is None:
            return []

        base_ioctl = sub_acc if sub_acc is not None else 0
        n_entries = min((count & 0xFFFF) + 1, 256)

        # ── Two-level table: byte index table + dword offset table ─────
        if two_level and byte_table_off is not None and dword_table_off is not None and base_va is not None:
            byte_table_va = base_va + byte_table_off
            dword_table_va = base_va + dword_table_off

            byte_rva = byte_table_va - image_base
            byte_raw = self.pe.get_bytes_at_rva(byte_rva, n_entries)
            if len(byte_raw) < n_entries:
                return []

            max_case = max(byte_raw[:n_entries]) + 1
            dword_rva = dword_table_va - image_base
            dword_raw = self.pe.get_bytes_at_rva(dword_rva, max_case * 4)
            if len(dword_raw) < max_case * 4:
                return []

            case_handlers: Dict[int, int] = {}
            for case_idx in range(max_case):
                rel = struct.unpack_from("<i", dword_raw, case_idx * 4)[0]
                case_handlers[case_idx] = base_va + rel

            handler_freq: Dict[int, int] = {}
            for idx in range(n_entries):
                case = byte_raw[idx]
                hva = case_handlers.get(case, 0)
                handler_freq[hva] = handler_freq.get(hva, 0) + 1
            default_va = max(handler_freq, key=lambda v: handler_freq[v]) if handler_freq else None

            results: List[Tuple[int, int]] = []
            seen_handlers: set = set()
            for idx in range(n_entries):
                case = byte_raw[idx]
                handler_va = case_handlers.get(case, 0)
                if handler_va == default_va:
                    continue
                if handler_va in seen_handlers:
                    continue
                seen_handlers.add(handler_va)

                if has_shr:
                    ioctl_code = base_ioctl + idx * 4
                else:
                    ioctl_code = base_ioctl + idx

                if is_valid_ioctl(ioctl_code):
                    results.append((ioctl_code, handler_va))

            return results

        # ── Single-level table: dword offset table ────────────────────
        rva = table_va - image_base
        raw = self.pe.get_bytes_at_rva(rva, n_entries * 4)
        if len(raw) < n_entries * 4:
            return []

        handler_vas = []
        for idx in range(n_entries):
            rel = struct.unpack_from("<i", raw, idx * 4)[0]
            handler_vas.append(table_va + rel)

        freq: Dict[int, int] = {}
        for hva in handler_vas:
            freq[hva] = freq.get(hva, 0) + 1
        default_va = max(freq, key=lambda v: freq[v]) if freq else None

        results: List[Tuple[int, int]] = []
        seen_handlers: set = set()
        for idx, handler_va in enumerate(handler_vas):
            if handler_va == default_va:
                continue
            if handler_va in seen_handlers:
                continue
            seen_handlers.add(handler_va)

            if has_shr:
                ioctl_code = base_ioctl + idx * 4
            else:
                ioctl_code = base_ioctl + idx

            if is_valid_ioctl(ioctl_code):
                results.append((ioctl_code, handler_va))

        return results

    # ── Main CFG walk ──────────────────────────────────────────────────────

    def reconstruct(self, dispatch_va: int, max_blocks: int = 500) -> Dict[int, int]:
        """Return {ioctl_code: handler_va} dict."""
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        work: List[Tuple[int, Optional[int], bool]] = [(dispatch_va, None, False)]
        visited: set = set()
        result: Dict[int, int] = {}

        while work and len(visited) < max_blocks:
            block_va, acc, has_shr = work.pop(0)
            if block_va in visited:
                continue
            visited.add(block_va)

            rva = block_va - image_base
            data = self.pe.get_bytes_at_rva(rva, 1024)
            if not data:
                continue

            insns = self.dis.disassemble_range(data, block_va, max_insns=120)
            i = 0
            while i < len(insns):
                insn = insns[i]

                # ── SUB-chain ──────────────────────────────────────────────
                # Ignore stack/base-pointer adjustments — only 32-bit GPRs
                # holding the IoControlCode count toward the accumulator.
                if insn.mnemonic == "sub" and len(insn.operands) == 2:
                    op0, op1 = insn.operands
                    _IOCTL_REGS = (
                        x86c.X86_REG_EAX, x86c.X86_REG_ECX, x86c.X86_REG_EDX,
                        x86c.X86_REG_EBX, x86c.X86_REG_ESI, x86c.X86_REG_EDI,
                        x86c.X86_REG_R8D, x86c.X86_REG_R9D, x86c.X86_REG_R10D,
                        x86c.X86_REG_R11D,
                    )
                    if (op0.type == x86c.X86_OP_REG and
                            op1.type == x86c.X86_OP_IMM and
                            op0.reg in _IOCTL_REGS):
                        delta = op1.imm & 0xFFFFFFFF
                        acc = (0 if acc is None else acc) + delta
                        has_shr = False
                        for j in range(i + 1, min(i + 4, len(insns))):
                            ji = insns[j]
                            if ji.mnemonic in ("je", "jz") and ji.operands:
                                jop = ji.operands[0]
                                if jop.type == x86c.X86_OP_IMM and is_valid_ioctl(acc):
                                    result[acc] = jop.imm
                                    work.append((jop.imm, None, False))
                                break
                            if ji.mnemonic in ("cmp", "jmp", "ret", "retn"):
                                break

                # ── AND mask — compiler masks out method/access bits before indexing ──
                elif insn.mnemonic == "and" and len(insn.operands) == 2:
                    op0, op1 = insn.operands
                    if op0.type == x86c.X86_OP_REG and op1.type == x86c.X86_OP_IMM:
                        mask = op1.imm & 0xFFFFFFFF
                        # Common pattern: and eax, 0xFFFFFFFC (mask out method bits)
                        # This doesn't change our accumulator tracking — just note it

                # ── SHR by 2 — compiler divided ioctl index before table ──
                elif insn.mnemonic == "shr" and len(insn.operands) == 2:
                    op1 = insn.operands[1]
                    if op1.type == x86c.X86_OP_IMM and (op1.imm & 0xFF) == 2:
                        has_shr = True

                # ── CMP — direct compare or jump-table bounds check ────────
                elif insn.mnemonic == "cmp" and len(insn.operands) == 2:
                    op1 = insn.operands[1]
                    if op1.type == x86c.X86_OP_IMM:
                        imm = op1.imm & 0xFFFFFFFF

                        jt_entries = self._try_read_jump_table(
                            insns, i, imm, acc, has_shr, image_base)
                        if jt_entries:
                            for code, hva in jt_entries:
                                result[code] = hva
                                work.append((hva, None, False))
                            break

                        # Tail of a SUB-chain: `sub reg,BASE; je h1; cmp reg,N; jne err`
                        # means the match handler IOCTL = BASE + N.
                        chain_code = None
                        if acc is not None and 0 < imm <= 0x200:
                            chain_code = acc + imm

                        effective = imm if is_valid_ioctl(imm) else chain_code
                        if effective and is_valid_ioctl(effective):
                            for j in range(i + 1, min(i + 5, len(insns))):
                                ji = insns[j]
                                if ji.mnemonic in ("je", "jz") and ji.operands:
                                    jop = ji.operands[0]
                                    if jop.type == x86c.X86_OP_IMM:
                                        result[effective] = jop.imm
                                        work.append((jop.imm, None, False))
                                    break
                                elif ji.mnemonic in ("jne", "jnz") and ji.operands:
                                    # match case is fall-through; skip any
                                    # lea/mov shims and record the next call
                                    # target as the true handler.
                                    handler_va = None
                                    for k in range(j + 1, min(j + 8, len(insns))):
                                        ki = insns[k]
                                        if ki.mnemonic == "call" and ki.operands:
                                            kop = ki.operands[0]
                                            if kop.type == x86c.X86_OP_IMM:
                                                handler_va = kop.imm
                                                break
                                        if ki.mnemonic in ("ret", "retn", "jmp"):
                                            break
                                    if handler_va is None and j + 1 < len(insns):
                                        handler_va = insns[j + 1].address
                                    result[effective] = handler_va
                                    jop = ji.operands[0]
                                    if jop.type == x86c.X86_OP_IMM:
                                        work.append((jop.imm, None, False))
                                    break
                                if ji.mnemonic in ("cmp", "jmp", "ret", "retn"):
                                    break

                # ── Unconditional JMP — follow preserving state ────────────
                elif insn.mnemonic == "jmp" and insn.operands:
                    jop = insn.operands[0]
                    if jop.type == x86c.X86_OP_IMM:
                        work.append((jop.imm, acc, has_shr))
                    break

                # ── End of block ───────────────────────────────────────────
                elif insn.mnemonic in ("ret", "retn"):
                    break

                i += 1

        return result
