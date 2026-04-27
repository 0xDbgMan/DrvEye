"""IDAPython annotation script generator.

Emits a script that, when run inside IDA against the same .sys file,
names the IRP_MJ_DEVICE_CONTROL dispatch handler, names each per-IOCTL
handler (IoctlHandler_0x0022E008 etc.), and attaches repeatable comments
that carry purpose, decoded method/access, bug classes, recovered struct
fields and known device names. Turns the report into RE acceleration.

The generated script is ImageBase-relative — it queries
`idaapi.get_imagebase()` at runtime so it works even if the file is
rebased in IDA.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, List

from drivertool.ioctl import decode_ioctl

if TYPE_CHECKING:
    from drivertool.pe_analyzer import PEAnalyzer
    from drivertool.scanner import VulnScanner


def _py_str(s: str) -> str:
    """Escape for embedding inside a triple-quoted Python string literal."""
    return s.replace("\\", "\\\\").replace('"""', r'\"\"\"')


# Severity scoring — used to prefix handler names so IDA's function
# list sorts juicy IOCTLs to the top.
_PRIM_SEV = {
    "code-exec":          ("CRIT_", 100),
    "arb-write":          ("CRIT_", 95),
    "dse-disable":        ("CRIT_", 95),
    "callback-removal":   ("CRIT_", 90),
    "etw-disable":        ("HIGH_", 85),
    "edr-token-downgrade":("HIGH_", 85),
    "ppl-bypass":         ("HIGH_", 85),
    "token-steal":        ("HIGH_", 85),
    "process-kill":       ("HIGH_", 80),
    "physical-rw":        ("HIGH_", 75),
    "msr-rw":             ("HIGH_", 75),
    "arb-read":           ("HIGH_", 70),
    "info-leak":          ("MED_",  60),
    "process-ctrl":       ("MED_",  50),
    "process-attach":     ("MED_",  45),
    "thread-inject":      ("MED_",  45),
}


def _name_prefix(prims: list, bugs: list) -> str:
    """Return ('CRIT_'|'HIGH_'|'MED_'|'') based on the strongest
    primitive or bug class. Empty when nothing dangerous found."""
    best = 0
    best_pfx = ""
    for p in prims:
        pfx, score = _PRIM_SEV.get(p, ("", 0))
        if score > best:
            best, best_pfx = score, pfx
    # Bug-class amplifiers: missing-probe / int-overflow-alloc /
    # length-unbounded warrant at least HIGH_.
    if "missing-probe" in bugs and best < 70:
        best, best_pfx = 70, "HIGH_"
    if "int-overflow-alloc" in bugs and best < 70:
        best, best_pfx = 70, "HIGH_"
    if "length-unbounded" in bugs and best < 60:
        best, best_pfx = 60, "MED_"
    return best_pfx


def _comment_for(code: int, scanner: "VulnScanner") -> str:
    """Build the repeatable comment for a single IOCTL handler."""
    decoded = decode_ioctl(code)
    purpose = scanner.ioctl_purposes.get(code, "")
    prims   = scanner.ioctl_primitives.get(code, [])
    bugs    = scanner.ioctl_bug_classes.get(code, [])
    fields  = scanner.ioctl_structs.get(code, [])
    beh     = scanner.ioctl_behaviors.get(code) or {}

    lines: List[str] = []
    lines.append(f"IOCTL {decoded['code']}  ({decoded['method_name']}, "
                 f"{decoded['access_name']})")
    if purpose:
        lines.append(f"purpose : {purpose}")
    if prims:
        lines.append(f"prims   : {', '.join(prims)}")
    if bugs:
        lines.append(f"bugs    : {', '.join(bugs)}")

    # NEW: gate state from CFG analysis
    ung = beh.get("ungated_sinks") or {}
    if ung:
        ungated = [hex(va) for va, st in ung.items() if st == "ungated"]
        gated = [hex(va) for va, st in ung.items() if st == "gated"]
        if ungated:
            lines.append(f"UNGATED sinks @ {', '.join(ungated)}")
        if gated:
            lines.append(f"gated   sinks @ {', '.join(gated)}")

    # NEW: shared-site convergence chips
    shared = getattr(scanner, "primitive_shared_sites", {}) or {}
    for (prim, va), codes in shared.items():
        if code in codes:
            peers = [c for c in codes if c != code]
            if peers:
                peer_str = ", ".join(f"0x{c:08X}" for c in peers[:3])
                lines.append(f"{prim} site @0x{va:X} shared with {peer_str}")
    wrapped = getattr(scanner, "ioctl_thin_wrapper_of", {}).get(code)
    if wrapped is not None:
        lines.append(f"thin wrapper of IOCTL 0x{wrapped:08X}")

    if fields:
        lines.append("input struct:")
        sz_names = {1: "BYTE", 2: "WORD", 4: "DWORD", 8: "QWORD"}
        for fld in sorted(fields, key=lambda f: f["offset"]):
            tn = sz_names.get(fld.get("size", 0), f"{fld.get('size', 0)}B")
            tag = fld.get("field_type") or fld.get("used_by") or ""
            tag_s = f"  [{tag}]" if tag else ""
            lines.append(f"  +0x{fld['offset']:02X}  {tn}{tag_s}")

    # NEW: backward-slice arg provenance for the dangerous calls
    ap = beh.get("arg_provenance") or {}
    if ap:
        lines.append("arg provenance (backward slice):")
        for call_va, provs in list(ap.items())[:4]:
            lines.append(f"  call @0x{call_va:X}:")
            for i, p in enumerate(provs):
                kind = p.get("kind", "")
                detail = (p.get("detail") or "")[:60]
                if kind in ("imm", "mem_input_buffer", "mem_stack_local",
                             "api_return"):
                    lines.append(f"    arg{i}: {kind}  ({detail})")
    return "\n".join(lines)


def _emit_struct_definitions(scanner: "VulnScanner") -> List[str]:
    """Emit IDAPython that creates a real struct type for each
    recovered IOCTL input layout, so when the user double-clicks the
    handler they get proper field display in the disasm."""
    out: List[str] = []
    if not scanner.ioctl_structs:
        return out
    out.append("# ── Recovered IOCTL input struct types ─────────────────")
    out.append("import ida_struct, ida_typeinf")
    out.append("def _add_struct(struct_name, fields):")
    out.append("    sid = ida_struct.get_struc_id(struct_name)")
    out.append("    if sid == idaapi.BADADDR:")
    out.append("        sid = ida_struct.add_struc(idaapi.BADADDR, struct_name)")
    out.append("    if sid == idaapi.BADADDR:")
    out.append("        return None")
    out.append("    s = ida_struct.get_struc(sid)")
    out.append("    if not s:")
    out.append("        return None")
    out.append("    for off, sz, name in fields:")
    out.append("        flag = {1: idaapi.byte_flag(),")
    out.append("                2: idaapi.word_flag(),")
    out.append("                4: idaapi.dword_flag(),")
    out.append("                8: idaapi.qword_flag()}.get(sz, idaapi.byte_flag())")
    out.append("        ida_struct.add_struc_member(s, name, off, flag, None, sz)")
    out.append("    return sid")
    out.append("")
    for code, fields in sorted(scanner.ioctl_structs.items()):
        struct_name = f"IoctlInput_0x{code:08X}"
        py_fields = []
        for fld in sorted(fields, key=lambda f: f["offset"]):
            sz = fld.get("size", 0)
            if sz not in (1, 2, 4, 8):
                continue
            field_name = (fld.get("field_type") or fld.get("used_by")
                          or f"field_{fld['offset']:X}")
            field_name = "".join(c if c.isalnum() else "_"
                                  for c in field_name) or f"f_{fld['offset']:X}"
            py_fields.append((fld["offset"], sz, field_name))
        if not py_fields:
            continue
        out.append(f"_add_struct('{struct_name}', {py_fields!r})")
    out.append("")
    return out


def _emit_call_site_renames(scanner: "VulnScanner") -> List[str]:
    """For shared call sites that are clearly the implementation of a
    dangerous primitive (kill / arb-write / etc), rename the call site
    itself with a meaningful label so the reverser jumps straight to
    'where the kill happens'."""
    out: List[str] = []
    image_base = None
    try:
        image_base = scanner.pe.pe.OPTIONAL_HEADER.ImageBase
    except Exception:
        return out
    shared = getattr(scanner, "primitive_shared_sites", {}) or {}
    if not shared:
        return out
    out.append("# ── Primitive implementation site comments ─────────────")
    seen_va = set()
    for (prim, va), codes in shared.items():
        if va in seen_va:
            continue
        seen_va.add(va)
        rva = va - image_base
        codes_s = ", ".join(f"0x{c:08X}" for c in codes[:3])
        cmt = (f"=== {prim.upper()} primitive (shared) === "
               f"reached via IOCTLs: {codes_s}")
        out.append(
            f"_set_addr_cmt(0x{rva:X}, '''{_py_str(cmt)}''')")
    out.append("")
    return out


def _find_dispatch_va(scanner: "VulnScanner") -> int:
    """Pull IRP_MJ_DEVICE_CONTROL handler VA from earlier findings."""
    for f in scanner.findings:
        if (f.title and "IRP_MJ_DEVICE_CONTROL" in f.title
                and "handler" in f.title.lower()):
            d = f.details or {}
            try:
                if "handler" in d:
                    return int(d["handler"], 16)
                if f.location and f.location.startswith("0x"):
                    return int(f.location, 16)
            except (ValueError, TypeError):
                pass
    return 0


def generate_ida_script(pe_info: dict, scanner: "VulnScanner",
                        pe_analyzer: "PEAnalyzer") -> str:
    """Return the IDAPython script as a string."""
    image_base = pe_info.get("image_base", 0) or pe_analyzer.pe.OPTIONAL_HEADER.ImageBase
    fname = os.path.basename(pe_info.get("filepath", "driver.sys"))
    sha = pe_info.get("sha256", "?")[:16]

    dispatch_va = _find_dispatch_va(scanner)

    # Build (handler_va_rva, name, comment) triples — RVAs so the script
    # rebases cleanly against whatever ImageBase IDA loads it at.
    handler_entries = []
    seen_handler_vas = {}
    for code in scanner.ioctl_codes:
        beh = scanner.ioctl_behaviors.get(code) or {}
        hva = beh.get("handler_va") or 0
        if not hva:
            continue
        rva = hva - image_base
        prims = scanner.ioctl_primitives.get(code, []) or []
        bugs = scanner.ioctl_bug_classes.get(code, []) or []
        # Severity prefix sorts juicy IOCTLs to the top of IDA's
        # function list (CRIT_ before HIGH_ before MED_).
        prefix = _name_prefix(prims, bugs)
        name = f"{prefix}IoctlHandler_{code:08X}"
        # When multiple IOCTLs share a handler VA, only emit the first
        # name but list all aliased codes in the comment.
        if hva in seen_handler_vas:
            seen_handler_vas[hva].append(code)
            continue
        seen_handler_vas[hva] = [code]
        cmt = _comment_for(code, scanner)
        handler_entries.append((rva, name, cmt, hva))

    # Augment comments with shared-handler aliases (post-pass)
    for i, (rva, name, cmt, hva) in enumerate(handler_entries):
        codes = seen_handler_vas.get(hva, [])
        if len(codes) > 1:
            alias_str = ", ".join(f"0x{c:08X}" for c in codes)
            cmt = f"(aliased IOCTLs: {alias_str})\n{cmt}"
            handler_entries[i] = (rva, name, cmt, hva)

    # Header comment (at dispatch handler) summarising device names + bugs
    header_lines: List[str] = [
        f"=== {fname}  sha256:{sha}... ===",
        f"IRP_MJ_DEVICE_CONTROL dispatch (auto-named).",
    ]
    if pe_analyzer.device_names:
        header_lines.append("Device names:")
        for n in pe_analyzer.device_names:
            header_lines.append(f"  {n}")
    bug_summary = sorted({c for cs in scanner.ioctl_bug_classes.values()
                          for c in cs})
    if bug_summary:
        header_lines.append(f"Bug classes seen: {', '.join(bug_summary)}")
    header_cmt = "\n".join(header_lines)

    # ── Emit script ────────────────────────────────────────────────────
    parts: List[str] = []
    parts.append(
        '"""Auto-generated by drivertool.\n'
        f"Target: {fname}  (sha256: {pe_info.get('sha256', '?')})\n"
        'Run inside IDA Pro:  File → Script file → this .py\n'
        'Annotates the dispatch handler and every recovered IOCTL handler.\n'
        '"""'
    )
    parts.append(
        "import idaapi, idc, ida_name, ida_funcs, ida_bytes\n"
        "\n"
        "BUILD_IMAGE_BASE = 0x{:X}  # ImageBase used at analysis time\n"
        "RUNTIME_BASE     = idaapi.get_imagebase()\n"
        "DELTA            = RUNTIME_BASE - BUILD_IMAGE_BASE\n"
        "\n"
        "def _set(va, name, cmt):\n"
        "    ea = va + DELTA\n"
        "    if not idc.is_loaded(ea):\n"
        "        print('[drivertool] skip 0x%X (not loaded)' % ea)\n"
        "        return\n"
        "    if not ida_funcs.get_func(ea):\n"
        "        ida_funcs.add_func(ea)\n"
        "    if name:\n"
        "        ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE)\n"
        "    if cmt:\n"
        "        idc.set_func_cmt(ea, cmt, 1)\n"
        "    print('[drivertool] %-40s @ 0x%X' % (name or '(comment only)', ea))\n"
        "\n"
        "def _set_addr_cmt(va, cmt):\n"
        "    \"\"\"Place a repeatable comment at any instruction address —\n"
        "    used for primitive call sites (e.g. ZwTerminateProcess at the\n"
        "    shared kill site). NOT a function rename.\"\"\"\n"
        "    ea = va + DELTA\n"
        "    if not idc.is_loaded(ea):\n"
        "        return\n"
        "    idc.set_cmt(ea, cmt, 1)\n"
        "    print('[drivertool] addr-cmt @ 0x%X' % ea)\n"
        "\n"
        "print('=== drivertool annotation pass ===')\n".format(image_base)
    )

    if dispatch_va:
        rva = dispatch_va - image_base
        parts.append(
            f"_set(0x{rva:X}, 'IrpDeviceControl', \"\"\"{_py_str(header_cmt)}\"\"\")"
        )

    for rva, name, cmt, _hva in handler_entries:
        parts.append(
            f"_set(0x{rva:X}, '{name}', \"\"\"{_py_str(cmt)}\"\"\")"
        )

    # NEW: emit IDA struct types for recovered IOCTL inputs
    parts.extend(_emit_struct_definitions(scanner))

    # NEW: rename / comment the actual primitive call sites
    parts.extend(_emit_call_site_renames(scanner))

    parts.append("\nprint('=== drivertool annotation pass complete ===')\n")
    return "\n".join(parts)
