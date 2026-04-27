"""CLI entry point — argument parsing and orchestration."""
from __future__ import annotations

import argparse
import logging
import os
import sys
import textwrap
from typing import Dict, List

logger = logging.getLogger(__name__)

import pefile

from drivertool.constants import (
    DANGEROUS_IMPORTS, LOLDRIVERS_HASHES, MS_DRIVER_BLOCKLIST, Severity,
)
from drivertool.models import Finding
from drivertool.pe_analyzer import PEAnalyzer
from drivertool.disassembler import Disassembler
from drivertool.scanner import VulnScanner
from drivertool.source_scanner import SourceScanner
from drivertool.poc_generator import PoCGenerator
from drivertool.output import NarrativeOutput
from drivertool.ioctl import IOCTL_METHOD_LABEL, decode_ioctl
from drivertool.generators.compiler import compile_poc, check_gcc
from drivertool.generators.yara_rule import generate_yara_rule
from drivertool.generators.json_export import export_json
from drivertool.generators.fuzzer import generate_fuzzer_harness
from drivertool.generators.tracer import generate_ioctl_tracer
from drivertool.generators.check_script import generate_check_script
from drivertool.generators.ida_script import generate_ida_script
from drivertool.object_resolver import ObjectResolver


def main():
    parser = argparse.ArgumentParser(
        description="drivertool.py — Windows Driver Static Analysis & Bug Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python drivertool.py driver.sys
              python drivertool.py driver.sys --save-pocs
              python drivertool.py driver.sys --source driver.c dispatch.c
              python drivertool.py driver.sys --output-dir ./results --save-pocs
              python drivertool.py driver.sys --verbose --no-color
        """),
    )
    parser.add_argument("drivers", nargs="*",
                        help="One or more .sys driver files to analyze")
    parser.add_argument("--source", nargs="+", help="Optional C/C++ source files to scan")
    parser.add_argument("--output-dir", default="pocs_output",
                        help="Directory for PoC output (default: pocs_output)")
    parser.add_argument("--save-pocs", action="store_true",
                        help="Write generated PoC scripts to disk")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all findings detail + entry point disassembly")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--compile", action="store_true",
                        help="Auto-compile generated PoC .c files to .exe (requires MinGW gcc)")
    parser.add_argument("--device", metavar="NAME",
                        help="Override device name for PoCs (e.g. MyDriver → opens \\\\.\\MyDriver)")
    parser.add_argument("--json", metavar="FILE",
                        help="Write full analysis results to a JSON file")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Write the human-readable report to FILE "
                             "(disables ANSI colors automatically)")
    parser.add_argument("--fuzzer", action="store_true",
                        help="Generate Python + C IOCTL fuzzing harnesses in --output-dir")
    parser.add_argument("--check-script", action="store_true",
                        help="Generate a PowerShell script to check driver status on Windows")
    parser.add_argument("--tracer", action="store_true",
                        help="Generate IOCTL runtime tracer (probes each IOCTL to discover what it does)")
    parser.add_argument("--ida", metavar="FILE",
                        help="Write an IDAPython annotation script to FILE "
                             "(names dispatch + per-IOCTL handlers, attaches "
                             "purpose/bugs/struct comments)")
    parser.add_argument("--live-check", action="store_true",
                        help="Synchronizes the tool with the latest Microsoft "
                             "kernel trust, certificate revocation, and vulnerable "
                             "driver block policies in real-time. Fetches "
                             "authroot.stl, disallowedcert.stl, and the MS "
                             "vulnerable-driver blocklist from Windows Update.")
    parser.add_argument("--loldrivers", action="store_true",
                        help="Extend the driver database by adding external "
                             "intelligence sources. Fetches and parses vulnerable "
                             "drivers from LOLDrivers (GitHub + API), Microsoft "
                             "Vulnerable Driver Block List, MalwareBazaar, "
                             "Hybrid Analysis, and HEVD. Normalizes all entries "
                             "into a unified local database and updates cache "
                             "incrementally.")
    parser.add_argument("--no-live-policy", action="store_true",
                        help="Ignore the cached MS trust lists (fall back to "
                             "the built-in KERNEL_TRUSTED_ROOTS snapshot).")
    args = parser.parse_args()

    if not args.drivers and not args.loldrivers:
        parser.error("the following arguments are required: drivers (or use "
                     "--loldrivers to fetch the dataset without analysis)")

    # --output FILE: redirect stdout to FILE for the duration of the run.
    # Force --no-color in that mode so the file is plain text.
    _output_fp = None
    if args.output:
        _output_fp = open(args.output, "w", encoding="utf-8")
        _orig_stdout = sys.stdout
        sys.stdout = _output_fp
        args.no_color = True
        import atexit
        def _restore_stdout():
            sys.stdout = _orig_stdout
            try:
                _output_fp.flush(); _output_fp.close()
            except Exception:
                logger.debug("Failed to flush/close output file", exc_info=True)
        atexit.register(_restore_stdout)

    out = NarrativeOutput(no_color=args.no_color)

    # ── Credit banner ─────────────────────────────────────────────────────
    # Shown once at startup before any analysis. Honours --no-color and
    # --output FILE redirection (the banner lands in the report file too,
    # giving credit to the author no matter where the run was directed).
    _banner_color = "" if args.no_color else "\x1b[36m"   # cyan
    _banner_dim   = "" if args.no_color else "\x1b[2m"
    _banner_reset = "" if args.no_color else "\x1b[0m"
    print(f"{_banner_color}"
          f"╔═════════════════════════════════════════╗\n"
          f"║   DrvEye  Windows Driver Rev&Analysis   ║\n"
          f"║   {_banner_dim}Credit:{_banner_reset}{_banner_color} @0xDbgMan                     ║\n"
          f"╚═════════════════════════════════════════╝"
          f"{_banner_reset}")

    # ── Live Microsoft trust / revocation lists ──────────────────────────
    # Merges authroot.stl thumbprints into KERNEL_TRUSTED_ROOTS so the
    # chain anchor check matches real kernel behaviour. Silent on cache
    # miss; loud on --live-check.
    policy_meta = {"loaded": False}
    if not args.no_live_policy:
        try:
            from drivertool import policy_cache as _pc
            if args.live_check:
                out.info("Updating Microsoft trust lists from Windows Update...")
                try:
                    sizes = _pc.update_cache()
                    out.good(
                        f"  Updated: " +
                        ", ".join(f"{n}={s}B" for n, s in sizes.items()))
                except Exception as e:
                    out.warn(f"  Update failed: {e}")
                out.info("Updating Microsoft vulnerable-driver block list...")
                try:
                    bl_sha1, bl_sha256, _age = _pc.load_driver_blocklist(
                        auto_fetch=True, max_age_days=0)
                    out.good(
                        f"  Blocklist: {len(bl_sha1)} SHA-1 + "
                        f"{len(bl_sha256)} SHA-256 hashes")
                except Exception as e:
                    out.warn(f"  Blocklist update failed: {e}")
            trusted, disallowed, meta = _pc.load_trusted_thumbprints(
                auto_fetch=False)
            bl_sha1, bl_sha256, bl_age = _pc.load_driver_blocklist(
                auto_fetch=False)
            if bl_sha1 or bl_sha256:
                from drivertool.constants import (
                    LIVE_BLOCKED_DRIVER_HASHES_SHA1,
                    LIVE_BLOCKED_DRIVER_HASHES_SHA256,
                )
                LIVE_BLOCKED_DRIVER_HASHES_SHA1 |= bl_sha1
                LIVE_BLOCKED_DRIVER_HASHES_SHA256 |= bl_sha256
                age_str = (f"{bl_age:.1f}d old"
                           if bl_age != float("inf") else "?")
                out.info(f"Live MS block list: {len(bl_sha1)} SHA-1 + "
                         f"{len(bl_sha256)} SHA-256 hashes ({age_str})")
            disallow_sha1 = disallowed.get(20, set()) if isinstance(disallowed, dict) else set()
            disallow_sha256 = disallowed.get(32, set()) if isinstance(disallowed, dict) else set()
            if disallow_sha1 or disallow_sha256:
                from drivertool.constants import (
                    LIVE_DISALLOWED_THUMBPRINTS,
                    LIVE_DISALLOWED_THUMBPRINTS_SHA256,
                )
                LIVE_DISALLOWED_THUMBPRINTS |= disallow_sha1
                LIVE_DISALLOWED_THUMBPRINTS_SHA256 |= disallow_sha256
            if trusted:
                added = _pc.merge_into_kernel_trusted(trusted)
                total_disallowed = len(disallow_sha1) + len(disallow_sha256)
                policy_meta = {
                    "loaded": True,
                    "trusted_count": len(trusted),
                    "added": added,
                    "disallowed_count": total_disallowed,
                    "authroot_age_days": meta.get("authroot.stl_age_days"),
                    "disallowed_age_days": meta.get("disallowedcert.stl_age_days"),
                }
                age = policy_meta["authroot_age_days"]
                age_str = f"{age:.1f}d old" if age != float("inf") else "?"
                out.info(f"Live MS trust list: {len(trusted)} roots, "
                         f"{total_disallowed} disallowed ({age_str}) "
                         f"[+{added} new to kernel trust]")
        except Exception as e:
            out.warn(f"Policy cache unavailable: {e}")

    # ── External driver intelligence fetch ──────────────────────────────
    if args.loldrivers:
        try:
            from drivertool.intel_fetcher import IntelFetcher
            fetcher = IntelFetcher()
            out.info("Extending driver database from external intel sources...")
            stats = fetcher.fetch_all(force=True)
            total_entries = sum(v[0] for v in stats.values())
            total_binaries = sum(v[1] for v in stats.values())

            for src, (entries, binaries) in stats.items():
                status = "[+]" if entries or binaries else "[-]"
                out.info(
                    f"  {status} {src}: {entries} entries, {binaries} binaries")

            # Populate the global hash lookup so analysis can match against it
            hashes = fetcher.get_hashes()
            if hashes:
                from drivertool.constants import LOLDRIVERS_HASHES
                LOLDRIVERS_HASHES.update(hashes)
                out.good(
                    f"Total unified DB: {len(fetcher.get_entries())} unique "
                    f"samples, {fetcher.count_binaries()} local binaries")
                out.info(
                    f"Cache: {fetcher.cache_dir}/intel_db.json")
                out.good("Ready for analysis")
            else:
                out.warn("No intelligence data was retrieved from any source")
        except Exception as e:
            out.warn(f"Intel fetch failed: {e}")
        if not args.drivers:
            return 0

    # ── Driver loop — process each input in turn ────────────────────────
    overall_code = 0
    for _idx, _driver_path in enumerate(args.drivers):
        if _idx > 0:
            print("\n" + "=" * 70 + "\n")
        if not os.path.isfile(_driver_path):
            out.warn(f"File not found: {_driver_path}")
            overall_code = max(overall_code, 1)
            continue
        args.driver = _driver_path   # existing body reads args.driver
        code = _run_single_driver(args, out, policy_meta)
        if code > overall_code:
            overall_code = code
    sys.exit(overall_code)


def _run_single_driver(args, out, policy_meta) -> int:
    """Analyze a single driver and return an exit code.

    Returns:
        0 = no issues, 1 = high-severity findings or load error,
        2 = critical-severity findings.
    """
    # ── 1. Parse PE ──────────────────────────────────────────────────────
    out.info(f"Analysis started: {os.path.basename(args.driver)}")
    try:
        pe_analyzer = PEAnalyzer(args.driver)
        pe_info = pe_analyzer.parse()
    except pefile.PEFormatError as e:
        out.warn(f"Invalid PE file: {e}")
        return 1
    except Exception as e:
        out.warn(f"Error loading file: {e}")
        return 1

    out.info(f"SHA-256  : {pe_info['sha256']}")
    out.info(f"imphash  : {pe_info['imphash']}")
    if pe_info['sha256'] in LOLDRIVERS_HASHES:
        out.warn(f"KNOWN VULNERABLE DRIVER: {LOLDRIVERS_HASHES[pe_info['sha256']]}")
    out.info(f"Architecture: {pe_info['arch']} | Kernel Driver: "
             f"{'Yes' if pe_info['is_driver'] else 'No'}")
    out.info(f"Image Base: 0x{pe_info['image_base']:X} | "
             f"Imports: {pe_info['num_imports']} | Sections: {pe_info['num_sections']}")
    # Version info
    vi = pe_info.get("version_info", {})
    if vi:
        fields = ["OriginalFilename", "CompanyName", "FileVersion", "FileDescription"]
        vi_str = " | ".join(f"{k}: {vi[k]}" for k in fields if k in vi)
        if vi_str:
            out.info(f"VersionInfo: {vi_str}")
    # Security features summary
    sf = pe_info.get("security_features", {})
    if sf:
        on  = [k for k, v in sf.items() if v  and k != "HVCI_COMPATIBLE"]
        off = [k for k, v in sf.items() if not v and k != "HVCI_COMPATIBLE"]
        hvci = "HVCI:YES" if sf.get("HVCI_COMPATIBLE") else "HVCI:NO"
        out.info(f"Mitigations ON : {', '.join(on) if on else 'none'}")
        if off:
            out.warn(f"Mitigations OFF: {', '.join(off)}  [{hvci}]")

    # Certificate info summary
    ci = pe_info.get("certificate", {})
    if ci.get("signed"):
        signer = ci.get("signer_cn", "Unknown")
        signer_org = ci.get("signer_org", "")
        issuer = ci.get("signer_issuer", "Unknown")
        serial = ci.get("signer_serial", "")
        expired = " [EXPIRED]" if ci.get("signer_expired") else ""
        self_signed = " [SELF-SIGNED]" if ci.get("signer_self_signed") else ""
        key_info = f"{ci.get('signer_key_type', '?')}-{ci.get('signer_key_size', '?')}"
        not_before = ci.get("certificates", [{}])
        # Find signer cert validity
        signer_not_before = ""
        signer_not_after = ci.get("signer_not_after", "")
        for c in ci.get("certificates", []):
            if c.get("subject_cn") == signer:
                signer_not_before = c.get("not_before", "")
                signer_not_after = c.get("not_after", "")
                break

        print()
        out.info("─── Authenticode Signature ───")

        # ── One-line status verdict ─────────────────────────────────
        sig_valid     = ci.get("signature_valid")
        pe_match      = ci.get("pe_hash_match")
        nested_sigs   = ci.get("nested_signatures") or []
        any_nested_ok = any(
            n.get("signature_valid") is True and
            n.get("pe_hash_match") is not False
            for n in nested_sigs)
        anchor        = ci.get("chain_anchor") or {}
        anchor_kind   = anchor.get("kind", "unknown")
        kernel_ok     = anchor.get("trusted_for_kernel", False)

        status_bits = []
        if sig_valid is True and pe_match is not False:
            status_bits.append("crypto OK")
        elif any_nested_ok:
            status_bits.append("primary BAD / nested OK")
        elif sig_valid is False:
            status_bits.append(f"CRYPTO FAIL ({ci.get('signature_error', '?')})")
        elif pe_match is False:
            status_bits.append("PE HASH MISMATCH (tampered)")
        else:
            status_bits.append("crypto unchecked")

        if kernel_ok:
            status_bits.append(f"anchor [{anchor_kind}]")
        else:
            status_bits.append(f"anchor UNTRUSTED [{anchor_kind}]")

        if ci.get("signer_expired"):
            _ts_time = ci.get("countersig_time") or ""
            if _ts_time:
                status_bits.append(
                    f"cert expired (grandfathered by TS {_ts_time[:10]})")
            else:
                status_bits.append("cert EXPIRED (no timestamp)")
        if ci.get("signer_self_signed"):
            status_bits.append("SELF-SIGNED")

        all_good = ((sig_valid is True or any_nested_ok) and
                    pe_match is not False and kernel_ok and
                    not ci.get("signer_self_signed"))
        status_fn = out.good if all_good else out.warn
        status_fn(f"  Status    : {' · '.join(status_bits)}")

        # ── Primary signature line ──────────────────────────────────
        primary_alg = ci.get("pe_hash_algorithm", "?").upper()
        primary_tag = "✓" if (sig_valid is True and pe_match is not False) else "✗"
        out.info(f"  Primary   : {primary_alg} [{primary_tag}]  "
                 f"signed by {signer}")
        out.info(f"             → {issuer}")

        # ── Nested signatures ──────────────────────────────────────
        for n in nested_sigs:
            n_alg = (n.get("digest_algorithm") or "?").upper()
            n_ok  = (n.get("signature_valid") is True and
                     n.get("pe_hash_match") is not False)
            n_tag = "✓" if n_ok else "✗"
            detail = []
            if n.get("signature_valid") is False:
                detail.append(n.get("signature_error") or "crypto fail")
            if n.get("pe_hash_match") is False:
                detail.append("PE hash mismatch")
            suffix = f"  ({', '.join(detail)})" if detail else ""
            out.info(f"  Nested    : {n_alg} [{n_tag}]{suffix}")

        # ── Timestamp ──────────────────────────────────────────────
        ts_time    = ci.get("countersig_time") or ""
        ts_source  = ci.get("countersig_source") or ""
        ts_valid   = ci.get("timestamp_valid")
        ts_bind_ok = ci.get("timestamp_binding_ok", False)
        ts_signer  = ci.get("timestamp_signer", "")
        if ts_source:
            if ts_valid is True:
                v, bad = "verified", False
            elif ts_valid is False and ts_bind_ok:
                # Binding OK but TSA crypto failed — legacy TSA; Windows accepts.
                v, bad = "accepted (legacy TSA — bind OK)", False
            elif ts_valid is False:
                v, bad = "BINDING FAIL", True
            else:
                v, bad = "unchecked", False
            tline = f"  Timestamp : {ts_time[:10] if ts_time else '?'}  [{v}]"
            if ts_source == "rfc3161":
                tline += "  (RFC3161)"
            if ts_signer:
                tline += f"  via {ts_signer}"
            (out.warn if bad else out.info)(tline)
        else:
            out.warn("  Timestamp : none")

        # ── Anchor ─────────────────────────────────────────────────
        anchor_name = anchor.get("matched_name", "")
        out.info(f"  Anchor    : {anchor_name or '—'}  "
                 f"[{'kernel-trusted' if kernel_ok else 'NOT kernel-trusted'}]")

        # ── HVCI / WHQL / EV markers ───────────────────────────────
        hvci_bits = []
        if ci.get("has_whql_eku"):
            hvci_bits.append("WHQL EKU")
        if ci.get("has_ev_cert"):
            hvci_bits.append("EV cert")
        if ci.get("page_hashes_present"):
            hvci_bits.append(f"page-hashes:{ci.get('page_hashes_algorithm', '?')}")
        if hvci_bits:
            out.info(f"  HVCI Prereqs: {', '.join(hvci_bits)}")
        else:
            out.warn("  HVCI Prereqs: none (no WHQL/EV/page-hashes)")

        # ── Signer identity ────────────────────────────────────────
        if signer_org:
            out.info(f"  Org       : {signer_org}")
        out.info(f"  Serial    : {serial.upper()}")
        out.info(f"  Key       : {key_info}")
        if signer_not_before:
            out.info(f"  Valid     : {signer_not_before[:10]} → {signer_not_after[:10]}")
        out.info(f"  Thumbprint: {ci.get('signer_thumbprint', 'N/A')}")

        # ── Chain ──────────────────────────────────────────────────
        chain_certs = ci.get("certificates", [])
        if len(chain_certs) > 1:
            out.info(f"  Chain ({len(chain_certs)} certs):")
            for idx, c in enumerate(chain_certs):
                cn = c.get("subject_cn", "?")
                iss_cn = c.get("issuer_cn", "?")
                exp = " [EXPIRED]" if c.get("expired") else ""
                ca = " [CA]" if c.get("is_ca") else ""
                cs = " [CodeSign]" if c.get("has_code_signing_eku") else ""
                out.info(f"    [{idx}] {cn}{ca}{cs}{exp}")
                out.info(f"        Issuer: {iss_cn}")
                out.info(f"        Serial: {c.get('serial', '?').upper()}")
                out.info(f"        Valid : {c.get('not_before', '?')[:10]} → "
                         f"{c.get('not_after', '?')[:10]}")

        # Revoked check
        from drivertool.constants import KNOWN_REVOKED_CERTS
        serial_lower = serial.lower().lstrip("0")
        for rev_serial, rev_desc in KNOWN_REVOKED_CERTS.items():
            if serial_lower and serial_lower == rev_serial.lower().lstrip("0"):
                out.warn(f"  REVOKED CERT: {rev_desc}")
                break
        print()
    else:
        if ci.get("likely_catalog_signed"):
            out.info(
                f"Certificate: no embedded signature — likely catalog-signed  "
                f"({ci.get('catalog_sign_reason', '')})")
        else:
            out.warn("Certificate: UNSIGNED — no Authenticode signature found")

    # Quick load compatibility note (will be detailed in findings)
    sha = pe_info['sha256']
    if sha in MS_DRIVER_BLOCKLIST:
        out.warn(f"MS BLOCK LIST: {MS_DRIVER_BLOCKLIST[sha]}")
    if sha in LOLDRIVERS_HASHES:
        out.warn(f"LOLDrivers MATCH: {LOLDRIVERS_HASHES[sha]}")

    if not pe_analyzer.is_driver:
        out.warn("File does not appear to be a kernel driver (Subsystem != NATIVE)")

    # ── 2. Disassembler + device name detection (collect, print later) ───
    dis = Disassembler(pe_analyzer.is_64bit)

    _device_name_override = args.device if hasattr(args, "device") else None
    if not _device_name_override:
        # MmGetSystemRoutineAddress resolver — must run FIRST so all
        # subsequent tracers see dynamically-resolved function pointers
        # as synthetic IAT entries.
        pe_analyzer.resolve_mm_get_system_routine_address(dis)

        # Disasm trace
        traced_names = pe_analyzer.trace_device_names_disasm(pe_analyzer.iat_map, dis)
        for tn in traced_names:
            if tn not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(tn)

        # XOR decode
        xor_names = pe_analyzer.scan_xor_encoded_strings(dis)
        for xn in xor_names:
            if xn not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(xn)

        # XMM-stack emulator (movdqa/movaps + stack spill + XOR decode)
        xmm_names = pe_analyzer.extract_xmm_stacked_device_names(dis)
        for xn in xmm_names:
            if xn not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(xn)

        # Stack-packed (non-XMM) immediate-store reconstruction
        for sp in pe_analyzer.extract_stack_packed_device_names(dis):
            if sp not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(sp)

        # .data UNICODE_STRING initializer (lea literal; mov [data_var], reg)
        for di in pe_analyzer.extract_data_unicode_string_initializers(dis):
            if di not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(di)

        # Format-string device name templates (RtlStringCbPrintfW/swprintf_s)
        for fn in pe_analyzer.find_format_device_names():
            if fn not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(fn)

        # Registry-service-derived names (\Registry\Machine\...\Services\<svc>)
        reg_templates, reg_refs = pe_analyzer.extract_registry_service_names()
        for rn in reg_templates:
            if rn not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(rn)
        pe_analyzer.registry_refs = reg_refs

        # Runtime string-concat composed names (wcscat/RtlAppendUnicode*/swprintf)
        for cn in pe_analyzer.extract_concat_device_names(dis):
            if cn not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(cn)

        # Raw 16-byte GUID structs passed to IoRegisterDeviceInterface et al.
        for gn in pe_analyzer.extract_guid_interface_structs(dis):
            if gn not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(gn)

        # Stack-built GUID immediate-stores (mov [rsp+N], imm … lea rdx, [rsp+N])
        for gi in pe_analyzer.extract_guid_immediate_stores(dis):
            if gi not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(gi)

        # Stack-built UNICODE_STRING structs (lea reg, [rsp+N]; Buffer at +8)
        for sn in pe_analyzer.extract_stack_unicode_string_names(dis):
            if sn not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(sn)

        # Full-CPU emulation of DriverEntry (Unicorn). Captures names built
        # via arithmetic, custom ciphers, runtime registry fetches — any
        # pattern a static tracer misses. No-op if Unicorn isn't installed.
        try:
            from drivertool.emulator import (
                extract_emulated_device_names, UNICORN_AVAILABLE,
            )
            if UNICORN_AVAILABLE:
                for en in extract_emulated_device_names(pe_analyzer):
                    if en not in pe_analyzer.device_names:
                        pe_analyzer.device_names.append(en)
        except Exception:
            logger.debug("Emulated device-name extraction failed", exc_info=True)

        # POBJECT_ATTRIBUTES.ObjectName (ZwCreateSymbolicLinkObject, ZwOpenFile,
        # FltCreateCommunicationPort, ...). Registry: hits are routed to
        # registry_refs. Port: hits (FltCreateCommunicationPort) land in
        # minifilter_ports. Everything else → device_names.
        for on in pe_analyzer.extract_object_attributes_names(dis):
            if on.startswith("Registry:"):
                if on not in pe_analyzer.registry_refs:
                    pe_analyzer.registry_refs.append(on)
            elif on.startswith("Port:"):
                port_name = on[len("Port:"):]
                if port_name not in pe_analyzer.minifilter_ports:
                    pe_analyzer.minifilter_ports.append(port_name)
            elif on not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(on)

        # Dynamic templates — bare-prefix + Rtl*/Zw* composition pattern.
        # Surfaces drivers whose name is built at runtime from the service
        # registry key (e.g. EnCase EnPortv.sys / Slayer.sys). Suppress a
        # template for any prefix where we already have a concrete name —
        # a generic placeholder is only useful when we have nothing better.
        _concrete_prefixes = {
            p for n in pe_analyzer.device_names
            for p in ("\\Device\\", "\\DosDevices\\",
                       "\\??\\", "\\GLOBAL??\\")
            if n.startswith(p) and len(n) > len(p) and "%" not in n
            and not n[len(p):].startswith(("<", "_root_"))
        }
        for dn in pe_analyzer.extract_dynamic_device_templates(dis):
            pfx = next((p for p in ("\\Device\\", "\\DosDevices\\",
                                      "\\??\\", "\\GLOBAL??\\")
                        if dn.startswith(p)), None)
            if pfx in _concrete_prefixes and "<" in dn:
                continue
            if dn not in pe_analyzer.device_names:
                pe_analyzer.device_names.append(dn)

        # Drop strict-prefix duplicates (e.g. truncated reconstruction of a
        # longer recovered name). Format templates (containing %) are kept.
        # Also synthesize a full `\DosDevices\{GUID}` symlink when we have
        # the matching `\Device\{GUID}` but only a truncated symlink.
        import re as _re
        _guid_re = _re.compile(r"\\Device\\(\{[0-9A-Fa-f\-]+\})")
        full_guids = {m.group(1) for n in pe_analyzer.device_names
                      for m in [_guid_re.match(n)] if m}
        completed: list = []
        for n in pe_analyzer.device_names:
            if (n.startswith("\\DosDevices\\{") and not n.rstrip().endswith("}")):
                truncated = n[len("\\DosDevices\\"):]
                match = next((g for g in full_guids if g.startswith(truncated)),
                             None)
                if match:
                    completed.append("\\DosDevices\\" + match)
                    continue
            completed.append(n)
        pe_analyzer.device_names = completed

        # GUID body fragments (e.g. "\Device\680-ADDD") often come from
        # the multi-byte XOR scan latching onto a substring of the real
        # GUID. Drop a name when its tail (after the device-prefix) is a
        # substring of any GUID-style sibling's GUID body.
        _guid_body_re = _re.compile(r"^\\(?:Device|DosDevices|\?\?|GLOBAL\?\?)"
                                    r"\\\{([0-9A-Fa-f\-]+)\}$")
        guid_bodies = [m.group(1) for n in pe_analyzer.device_names
                       for m in [_guid_body_re.match(n)] if m]
        _prefixes = ("\\Device\\", "\\DosDevices\\",
                     "\\??\\", "\\GLOBAL??\\")
        survivors: list = []
        for n in pe_analyzer.device_names:
            if "%" in n:
                survivors.append(n); continue
            tail = next((n[len(p):] for p in _prefixes if n.startswith(p)), None)
            if tail and not tail.startswith("{") and len(tail) >= 4:
                if any(tail in body for body in guid_bodies):
                    continue  # fragment of a longer GUID name — drop
            survivors.append(n)
        pe_analyzer.device_names = survivors

        deduped: list = []
        for n in pe_analyzer.device_names:
            if "%" in n:
                deduped.append(n); continue
            is_prefix_of_other = any(
                other != n and "%" not in other and other.startswith(n)
                for other in pe_analyzer.device_names
            )
            if not is_prefix_of_other:
                deduped.append(n)
        pe_analyzer.device_names = deduped

        # Pair inference: synthesize the missing half of each device/symlink
        # pair when IoCreateSymbolicLink (or equivalent) is imported. Stored
        # separately from device_names so scanner/PoC/YARA consumers that do
        # prefix/tail math see only concrete, recovered names.
        pe_analyzer.inferred_names = [
            m for m in pe_analyzer.infer_symlink_pairs()
            if m not in pe_analyzer.device_names
        ]

    # ── 4. Vulnerability scan ────────────────────────────────────────────
    out.info("Scanning imports...")
    scanner = VulnScanner(pe_analyzer, dis)
    scanner.run_all()

    # ── Load Verdict Summary ─────────────────────────────────────────────
    # Collect load-related findings from scanner
    load_findings = [f for f in scanner.findings
                     if "Load compatibility" in (f.title or "")]
    if load_findings:
        lf = load_findings[0]
        load_details = lf.details or {}
        matrix = load_details.get("matrix") or {}
        can_load = load_details.get("can_load", "Unknown")

        print()
        # Per-config matrix — WILL LOAD / WILL NOT LOAD per Windows policy
        if matrix:
            # Overall headline
            default_ok = matrix.get("default", {}).get("verdict") == "WILL_LOAD"
            sb_ok      = matrix.get("secure_boot", {}).get("verdict") == "WILL_LOAD"
            hvci_ok    = matrix.get("hvci", {}).get("verdict") == "WILL_LOAD"
            any_ok     = any(m.get("verdict") == "WILL_LOAD" for m in matrix.values())

            if default_ok and sb_ok and hvci_ok:
                out.good("─── LOAD VERDICT: WILL LOAD (all modern Windows configs) ───")
            elif default_ok and sb_ok:
                out.good("─── LOAD VERDICT: WILL LOAD (blocked only under HVCI) ───")
            elif default_ok:
                out.warn("─── LOAD VERDICT: WILL LOAD only on relaxed configs ───")
            elif any_ok:
                out.warn("─── LOAD VERDICT: WILL LOAD only under test-signing ───")
            else:
                out.warn("─── LOAD VERDICT: WILL NOT LOAD on any supported config ───")

            labels = [
                ("default",      "Default Win10/11"),
                ("secure_boot",  "Secure Boot + DSE"),
                ("hvci",         "HVCI / Memory Integrity"),
                ("test_signing", "Test-signing mode"),
                ("s_mode",       "S Mode"),
            ]
            for key, label in labels:
                entry = matrix.get(key) or {}
                v = entry.get("verdict", "UNKNOWN")
                if v == "WILL_LOAD":
                    mark = out.COLORS.get(Severity.INFO, "")
                    tag = "WILL LOAD"
                elif v == "WILL_NOT_LOAD":
                    mark = out.COLORS.get(Severity.HIGH, "")
                    tag = "WILL NOT LOAD"
                elif v == "CONDITIONAL":
                    mark = out.COLORS.get(Severity.MEDIUM, "")
                    tag = "CONDITIONAL"
                else:
                    mark = ""; tag = v
                print(f"  {mark}{label:<25s}: {tag}{out.RESET}")
                # First blocker on next line for quick scan
                for b in (entry.get("blockers") or [])[:3]:
                    print(f"      • {b}")

            # Consolidated global blockers/passes block
            all_blockers, all_passes = set(), set()
            for m in matrix.values():
                for b in m.get("blockers", []):
                    all_blockers.add(b)
                for p in m.get("passes", []):
                    all_passes.add(p)
            if all_blockers:
                print()
                print(f"  {out.COLORS.get(Severity.HIGH, '')}All blockers found:{out.RESET}")
                for b in sorted(all_blockers):
                    print(f"    {out.COLORS.get(Severity.HIGH, '')}[BLOCKED]{out.RESET} {b}")
            if all_passes:
                print()
                print(f"  {out.COLORS.get(Severity.INFO, '')}Passes:{out.RESET}")
                for p in sorted(all_passes):
                    print(f"    {out.COLORS.get(Severity.INFO, '')}[PASS]{out.RESET} {p}")

            # ── Confidence line — what static analysis can and cannot prove
            print()
            conf_bits = []
            if policy_meta.get("loaded"):
                age = policy_meta.get("authroot_age_days")
                age_str = (f"{age:.1f}d old" if isinstance(age, (int, float))
                           and age != float("inf") else "unknown age")
                conf_bits.append(
                    f"live MS trust list loaded "
                    f"({policy_meta['trusted_count']} roots, "
                    f"{policy_meta.get('disallowed_count', 0)} disallowed, "
                    f"{age_str})")
            else:
                conf_bits.append(
                    "live MS trust list NOT loaded — using built-in "
                    "kernel-root snapshot (run --live-check for ground truth)")
            print(f"  {out.COLORS.get(Severity.INFO, '')}Confidence:{out.RESET} "
                  f"{' · '.join(conf_bits)}")
            print(f"    Static checks cover signature crypto, PE hash, "
                  f"chain anchor, HVCI prereqs, and MS block list.")
            print(f"    Not checked: live OCSP/CRL revocation, current WDAC "
                  f"policy, local test-signing / DSE state, page-hash integrity.")
        else:
            # Fallback to legacy flat summary
            if can_load == "True":
                out.good("─── LOAD VERDICT: LOADABLE ───")
                print("    This driver should load on modern Windows.")
            elif load_details.get("blockers"):
                out.warn(f"─── LOAD VERDICT: BLOCKED ───")
            else:
                out.info("─── LOAD VERDICT: UNKNOWN ───")
            for line in (lf.description or "").split("\n"):
                line = line.strip()
                if line:
                    if "[BLOCKED]" in line:
                        print(f"  {out.COLORS.get(Severity.HIGH, '')}  {line}{out.RESET}")
                    elif "[PASS]" in line:
                        print(f"  {out.COLORS.get(Severity.INFO, '')}  {line}{out.RESET}")
                    else:
                        print(f"    {line}")
        print()

    # ── Dangerous imports section ─────────────────────────────────────────
    seen_di: set = set()
    danger_imports = []
    for dll_funcs in pe_analyzer.imports.values():
        for func in dll_funcs:
            if (func in DANGEROUS_IMPORTS and
                    DANGEROUS_IMPORTS[func][0] >= Severity.MEDIUM and
                    func not in seen_di):
                seen_di.add(func)
                danger_imports.append(func)
    if danger_imports:
        crit_high = [f for f in danger_imports if DANGEROUS_IMPORTS[f][0] >= Severity.HIGH]
        medium    = [f for f in danger_imports if DANGEROUS_IMPORTS[f][0] == Severity.MEDIUM]
        parts = []
        if crit_high:
            parts.append("  [!] " + ", ".join(crit_high))
        if medium:
            parts.append("  [*] " + ", ".join(medium))
        print(f"[*] imports Function:")
        print("\n".join(parts))

    # ── IOCTL codes — annotated, one per line ─────────────────────────────
    if scanner.ioctl_codes:
        lines = []
        for code in scanner.ioctl_codes:
            dec     = decode_ioctl(code)
            method  = dec["method"]
            label   = IOCTL_METHOD_LABEL.get(method, "UNKNOWN")
            access  = dec["access_name"]
            purpose = scanner.ioctl_purposes.get(code, "")
            purpose_str = f"  → {purpose}" if purpose else ""

            # Build danger tags from behavior risk factors
            tags = set()
            beh = scanner.ioctl_behaviors.get(code, {})
            for rf in beh.get("risk_factors", []):
                if "terminate" in rf.lower():
                    tags.add("KILLER")
                elif "TOKEN STEAL" in rf:
                    tags.add("TOKEN STEAL")
                elif "PPL BYPASS" in rf:
                    tags.add("PPL BYPASS")
                elif "modify token" in rf.lower():
                    tags.add("TOKEN MODIFY")
                elif "Cross-process memory write" in rf:
                    tags.add("MEM WRITE")
                elif "create threads" in rf.lower():
                    tags.add("INJECTION")
            for rf in beh.get("risk_factors", []):
                if "CALLBACK REMOVAL" in rf or "CALLBACK CONTROL" in rf:
                    tags.add("CB REMOVE")
                elif "ETW DISABLE" in rf:
                    tags.add("ETW DISABLE")
                elif "EDR TOKEN DOWNGRADE" in rf:
                    tags.add("EDR DOWNGRADE")
                elif "RUNTIME RESOLVE" in rf:
                    tags.add("DSE RESOLVE")
                elif "Direct hardware" in rf:
                    tags.add("HW ACCESS")
                elif "Cross-process memory" in rf and "read" in rf.lower():
                    tags.add("MEM READ")
                elif "process attach" in rf.lower():
                    tags.add("ATTACH")
            if not tags and purpose:
                if purpose == "process kill":
                    tags.add("KILLER")
                elif purpose == "token steal":
                    tags.add("TOKEN STEAL")
                elif purpose == "ppl bypass":
                    tags.add("PPL BYPASS")
                elif purpose in ("mem write", "mem copy"):
                    tags.add("MEM WRITE")
                elif purpose == "mem read":
                    tags.add("MEM READ")
                elif purpose == "callback removal":
                    tags.add("CB REMOVE")
                elif purpose == "etw disable":
                    tags.add("ETW DISABLE")
                elif purpose == "edr token downgrade":
                    tags.add("EDR DOWNGRADE")
                elif purpose == "phys mem map":
                    tags.add("PHYS MAP")
                elif purpose in ("CR0 write", "CR4 write"):
                    tags.add("CR WRITE")
                elif purpose in ("MSR read", "MSR write"):
                    tags.add("MSR")
                elif purpose == "load driver":
                    tags.add("LOAD DRV")
                elif purpose == "create thread":
                    tags.add("INJECTION")
                elif purpose in ("file write", "delete file"):
                    tags.add("FILE OP")
                elif purpose in ("registry write", "registry delete"):
                    tags.add("REG OP")
                elif purpose == "runtime resolve":
                    tags.add("DSE RESOLVE")
                elif purpose == "adjust privileges":
                    tags.add("PRIV ADJUST")
                elif purpose == "token modify":
                    tags.add("TOKEN MODIFY")
                elif purpose == "process attach":
                    tags.add("ATTACH")
                elif purpose == "alloc memory":
                    tags.add("ALLOC")
                elif purpose == "change protection":
                    tags.add("PROTECT")
                elif purpose == "query system":
                    tags.add("SYSINFO")

            tag_str = "  " + " ".join(f"[!!{t}]" for t in sorted(tags)) if tags else ""
            danger  = "  [!] raw ptr — no probe" if method == 3 else ""
            any_acc = "  [!] any-user" if dec["access"] == 0 else ""
            slot_tag = ""
            origin = scanner.ioctl_origin_slot.get(code, 0x0E)
            if origin == 0x0D:
                slot_tag = "  [FSCTL]"
            elif origin == 0x0F:
                slot_tag = "  [INTERNAL]"
            if code in scanner.hash_dispatch_codes:
                slot_tag += "  [HASH-REVERSED]"

            # Handler VA — always show so reader can jump straight to IDA.
            hva = beh.get("handler_va") if beh else None
            if not hva:
                try:
                    hva = scanner._get_handler_va(code)
                except Exception:
                    hva = None
            hva_str = f"  @0x{hva:X}" if hva else "  @?"

            # Bug classes inline — moves the per-IOCTL triage info onto
            # the row it belongs to instead of a separate section.
            bug_classes = sorted(getattr(scanner, "ioctl_bug_classes", {}).get(code, []))
            bugs_str = f"  bugs={','.join(bug_classes)}" if bug_classes else ""

            # Path-gate chip — derived from CFG analysis on dangerous
            # API call sites. ``ungated`` = at least one dangerous API
            # is reachable from handler entry without passing through
            # SeAccessCheck / Probe / PreviousMode. ``gated`` = every
            # path to every dangerous sink hits a gate first.
            ung = (beh or {}).get("ungated_sinks") or {}
            gate_chip = ""
            if ung:
                if any(v == "ungated" for v in ung.values()):
                    gate_chip = "  [UNGATED-sink]"
                elif all(v == "gated" for v in ung.values()):
                    gate_chip = "  [gated]"

            # Convergence chips: shared primitive call-site or thin-wrapper
            # relationship. Both answer "is this really a distinct
            # primitive, or is it another entry point to something else?"
            convergence: list = []
            wrapped = getattr(scanner, "ioctl_thin_wrapper_of", {}).get(code)
            if wrapped is not None:
                convergence.append(f"wraps 0x{wrapped:08X}")
            shared = getattr(scanner, "primitive_shared_sites", {}) or {}
            site_peers: dict = {}  # primitive → [peer_codes]
            for (prim, _va), codes in shared.items():
                if code in codes:
                    peers = [c for c in codes if c != code]
                    if peers:
                        # Prefer the shortest primitive name for chip brevity
                        prim_label = prim.replace("-", "")[:12]
                        site_peers.setdefault(prim, peers)
            for prim, peers in site_peers.items():
                peer_str = ", ".join(f"0x{c:08X}" for c in peers[:2])
                if len(peers) > 2:
                    peer_str += f" +{len(peers) - 2}"
                convergence.append(f"shares {prim}-site with {peer_str}")
            conv_str = ""
            if convergence:
                conv_str = "  [" + " · ".join(convergence) + "]"

            lines.append(
                f"    0x{code:08X}{hva_str}  ({label}, {access})"
                f"{slot_tag}{purpose_str}{tag_str}{danger}{any_acc}"
                f"{bugs_str}{gate_chip}{conv_str}"
            )
        # Split count by slot for an honest header
        _fsctl_n = sum(1 for c in scanner.ioctl_codes
                       if scanner.ioctl_origin_slot.get(c) == 0x0D)
        _ioctl_n = len(scanner.ioctl_codes) - _fsctl_n
        header = f"[*] Detected IOCTL codes ({len(scanner.ioctl_codes)})"
        if _fsctl_n:
            header += f" — {_ioctl_n} IOCTL + {_fsctl_n} FSCTL"
        print(header + ":")
        print("\n".join(lines))

    # ── Exploit Primitives per IOCTL ──────────────────────────────────────
    if scanner.ioctl_primitives:
        print(f"\n[*] Exploit Primitives:")
        shared = getattr(scanner, "primitive_shared_sites", {}) or {}
        # Build {(prim, va): [codes]} already in reverse form
        for code, prims in sorted(scanner.ioctl_primitives.items()):
            decoded = decode_ioctl(code)
            purpose = scanner.ioctl_purposes.get(code, "")
            p_str = f" ({purpose})" if purpose else ""
            # Annotate each primitive with a shared-site tag when applicable
            prim_tokens = []
            for p in prims:
                tag = ""
                for (sprim, va), codes in shared.items():
                    if sprim == p and code in codes:
                        peers = [c for c in codes if c != code]
                        if peers:
                            tag = f" [@0x{va:X} shared]"
                        break
                prim_tokens.append(p + tag)
            print(f"    {decoded['code']}{p_str}: {', '.join(prim_tokens)}")

        # Unique-primitive count = after grouping shared-site codes
        counted: set = set()
        unique_primitives = 0
        for (prim, va), codes in shared.items():
            counted.update((prim, c) for c in codes)
            unique_primitives += 1  # one underlying primitive, multiple entries
        total_primitive_tags = sum(
            len(p) for p in scanner.ioctl_primitives.values())
        # Unique = tags not participating in any shared site + one-per-shared-site
        not_shared = total_primitive_tags - len(counted)
        unique_primitives += not_shared
        if shared:
            print(f"\n    ({unique_primitives} unique primitive implementation(s) "
                  f"across {total_primitive_tags} IOCTL tags — "
                  f"{len(shared)} shared by multiple IOCTLs)")

    # ── Bug-class legend (verbose only — per-IOCTL list now inline) ──────
    if scanner.ioctl_bug_classes and args.verbose:
        print(f"\n[!] Bug Class Legend:")
        for k in sorted({c for cs in scanner.ioctl_bug_classes.values()
                         for c in cs}):
            desc = scanner.BUG_CLASS_DESCRIPTIONS.get(k, "")
            if desc:
                print(f"    [{k}] {desc}")

    # ── IOCTL Structure Recovery (verbose only) ────────────────────────────
    if scanner.ioctl_structs and args.verbose:
        print(f"\n[*] Recovered IOCTL Input Structures:")
        for code, fields in sorted(scanner.ioctl_structs.items()):
            decoded = decode_ioctl(code)
            purpose = scanner.ioctl_purposes.get(code, "")
            p_str = f" ({purpose})" if purpose else ""
            print(f"    {decoded['code']}{p_str}:")
            for fld in sorted(fields, key=lambda f: f["offset"]):
                sz_names = {1: "BYTE", 2: "WORD", 4: "DWORD", 8: "QWORD"}
                type_name = sz_names.get(fld["size"], f"{fld['size']}B")
                access = fld["access"]
                constraint = f" == 0x{fld['constraint']:X}" if fld.get("constraint") is not None else ""
                ft = fld.get("field_type", "")
                used = fld.get("used_by", "")
                annotation = ""
                if ft:
                    annotation = f"  [{ft}]"
                elif used:
                    annotation = f"  → {used}"
                print(f"      +0x{fld['offset']:02X}  {type_name:6s}  ({access}{constraint}){annotation}")
    elif scanner.ioctl_structs and not args.verbose:
        print(f"\n[*] Recovered IOCTL Input Structures: {len(scanner.ioctl_structs)} IOCTLs (use -v to show)")

    # ── Device Access Security Audit ─────────────────────────────────────
    da = scanner.device_access
    if da:
        issues = da.get("issues", [])
        if issues:
            print(f"\n[!] Device Access Security:")
        else:
            print(f"\n[+] Device Access Security:")
        print(f"    Creation API   : {da.get('create_api', 'Unknown')}")
        dt = da.get('device_type')
        if dt is not None:
            print(f"    Device Type    : 0x{dt:X}")
        print(f"    Secure Open    : {'Yes' if da.get('secure_open') else 'No'}")
        print(f"    Exclusive      : {'Yes' if da.get('exclusive') else 'No'}")
        sddl = da.get('sddl')
        if sddl:
            print(f"    SDDL           : {sddl[:60]}{'...' if len(sddl) > 60 else ''}")
        else:
            print(f"    SDDL           : None (default permissive ACL)")
        symlinks = da.get('symlinks', [])
        if symlinks:
            for sl in symlinks:
                print(f"    Symlink        : {sl}  [user-accessible]")
        checks = da.get('create_checks', [])
        if checks:
            check_str = ", ".join(c for c in checks if c != "TRIVIAL_HANDLER")
            if check_str:
                print(f"    CREATE checks  : {check_str}")
        if "TRIVIAL_HANDLER" in (da.get('create_checks') or []):
            print(f"    CREATE handler : Trivial (no validation, instant SUCCESS)")
        if issues:
            print(f"    Issues ({len(issues)}):")
            for iss in issues:
                tag = "[!]" if iss in ("sddl_allows_everyone", "trivial_create_handler",
                                        "no_sddl", "uses_IoCreateDevice") else "[*]"
                pretty = iss.replace("_", " ").title()
                print(f"      {tag} {pretty}")

    # ── Per-IOCTL Handler Behavior Analysis ───────────────────────────────
    if scanner.ioctl_behaviors and args.verbose:
        print(f"\n[*] IOCTL Handler Behavior Analysis ({len(scanner.ioctl_behaviors)}):")
        for code, beh in sorted(scanner.ioctl_behaviors.items()):
            decoded = decode_ioctl(code)
            purpose = scanner.ioctl_purposes.get(code, "")
            p_str = f" ({purpose})" if purpose else ""
            api_count = len(beh["api_calls"])
            inline_count = len(beh["inline_ops"])

            has_risk = bool(beh["risk_factors"])
            marker = "!" if has_risk else "*"
            print(f"\n    [{marker}] {decoded['code']}{p_str}  @ 0x{beh['handler_va']:X}")

            categories: dict = {}
            for ac in beh["api_calls"]:
                categories.setdefault(ac["category"], []).append(ac)

            cat_order = ["CPU", "MEMORY", "IO", "TOKEN", "PROCESS",
                         "OBJECT", "POOL", "FILE", "REGISTRY", "DRIVER",
                         "CALLBACK", "ETW", "VALIDATION", "SYNC", "IRP", "OTHER"]
            for cat in cat_order:
                if cat not in categories:
                    continue
                apis = categories[cat]
                unique_apis = {}
                for ac in apis:
                    if ac["name"] not in unique_apis:
                        unique_apis[ac["name"]] = ac
                cat_tag = {
                    "CPU": "!!!", "MEMORY": "!!", "IO": "!!", "TOKEN": "!!",
                    "ETW": "!!", "PROCESS": "!", "VALIDATION": "+", "SYNC": ".",
                    "IRP": ".", "OTHER": "."
                }.get(cat, "*")
                api_names = ", ".join(unique_apis.keys())
                print(f"        [{cat_tag}] {cat:10s}: {api_names}")

            if beh["inline_ops"]:
                inline_types = sorted(set(op["type"] for op in beh["inline_ops"]))
                print(f"        [!!!] INLINE    : {', '.join(inline_types)}")

            checks = beh["security_checks"]
            if checks:
                unique_checks = sorted(set(checks))
                print(f"        [+] SECURITY   : {', '.join(unique_checks)}")
            else:
                print(f"        [-] SECURITY   : NONE")

            if not beh["irp_completion"]:
                print(f"        [-] IRP        : No completion detected")

            if beh["risk_factors"]:
                for rf in beh["risk_factors"]:
                    print(f"        [!] RISK: {rf}")

    # ── Device Names & Symbolic Links ─────────────────────────────────────
    print(f"\n[*] ─── Device Names & Symbolic Links ({len(pe_analyzer.device_names)}) ───")
    if not pe_analyzer.device_names:
        out.warn("    No device names recovered (may be runtime-constructed or obfuscated)")
        print("    Hint: pass --device NAME to set the symbolic-link manually")
    for name in pe_analyzer.device_names:
        is_format = "%" in name
        user_accessible = (name.startswith("\\DosDevices\\") or
                           name.startswith("\\??\\") or
                           name.startswith("\\GLOBAL??\\"))
        is_guid = name.startswith("DeviceInterface:")
        is_kernel = (name.startswith("\\Device\\") or
                     name.startswith("\\FileSystem\\") or
                     name.startswith("\\Callback\\"))
        if is_format:
            tag = "[~]"
            sfx = " (format template — constructed at runtime)"
        elif user_accessible:
            tag = "[+]"
            sfx = " (user-accessible)"
            if name.startswith("\\DosDevices\\"):
                open_path = "\\\\.\\%s" % name[len("\\DosDevices\\"):]
            elif name.startswith("\\??\\"):
                open_path = "\\\\.\\%s" % name[len("\\??\\"):]
            elif name.startswith("\\GLOBAL??\\"):
                open_path = "\\\\.\\%s" % name[len("\\GLOBAL??\\"):]
            else:
                open_path = None
            if open_path:
                sfx += f"  →  CreateFile(\"{open_path}\")"
        elif is_guid:
            tag = "[*]"
            sfx = " (device interface GUID — use SetupDiGetClassDevs)"
        elif is_kernel:
            tag = "[*]"
            sfx = " (kernel-only)"
        else:
            tag = "[*]"
            sfx = ""
        print(f"    {tag} {name}{sfx}")

    inferred = getattr(pe_analyzer, "inferred_names", [])
    for name in inferred:
        user_accessible = (name.startswith("\\DosDevices\\") or
                           name.startswith("\\??\\") or
                           name.startswith("\\GLOBAL??\\"))
        sfx = " (inferred pair — IoCreateSymbolicLink imported)"
        if user_accessible:
            if name.startswith("\\DosDevices\\"):
                open_path = "\\\\.\\%s" % name[len("\\DosDevices\\"):]
            elif name.startswith("\\??\\"):
                open_path = "\\\\.\\%s" % name[len("\\??\\"):]
            else:
                open_path = "\\\\.\\%s" % name[len("\\GLOBAL??\\"):]
            sfx += f"  →  CreateFile(\"{open_path}\")"
        print(f"    [?] {name}{sfx}")

    # ── Object Resolution (symlinks, ALPC ports, sections) ──────────────
    resolver = ObjectResolver(pe_analyzer).resolve()
    accessible = resolver.get_accessible_devices()
    if accessible:
        print(f"\n[+] ─── User-Mode Accessible Devices ({len(accessible)}) ───")
        for pair in accessible:
            short = ObjectResolver._short_name(pair.symlink) or pair.symlink
            print(f"    [+] \\\\.\\{short}  →  {pair.device}")
    if resolver.unlinked_devices:
        print(f"\n[!] ─── Devices WITHOUT User-Mode Symlink ({len(resolver.unlinked_devices)}) ───")
        print("    (These cannot be opened from user-mode via CreateFile)")
        for dev in resolver.unlinked_devices:
            print(f"    [-] {dev}")
    if resolver.hijack_risks:
        print(f"\n[!] ─── Symlink Hijack Risks ({len(resolver.hijack_risks)}) ───")
        print("    (Predictable symlink names without exclusive creation — "
              "attacker may create the symlink first)")
        for sl in resolver.hijack_risks:
            print(f"    [!] {sl}")
    if resolver.alpc_ports:
        print(f"\n[*] ─── ALPC / Communication Ports ({len(resolver.alpc_ports)}) ───")
        for p in resolver.alpc_ports:
            print(f"    [port] {p}")
    if resolver.sections:
        print(f"\n[*] ─── Named Sections ({len(resolver.sections)}) ───")
        for s in resolver.sections:
            print(f"    [section] {s}")
    if resolver.events:
        print(f"\n[*] ─── Named Events ({len(resolver.events)}) ───")
        for e in resolver.events:
            print(f"    [event] {e}")

    # ── Minifilter Communication Ports ────────────────────────────────────
    mfp = getattr(pe_analyzer, "minifilter_ports", [])
    if mfp:
        print(f"\n[*] ─── Minifilter Communication Ports ({len(mfp)}) ───")
        print("    (FltCreateCommunicationPort — user-mode entry points via "
              "FilterSendMessage / FilterConnectCommunicationPort)")
        for p in mfp:
            print(f"    [port] {p}")

    # ── Registry References ───────────────────────────────────────────────
    reg_refs = getattr(pe_analyzer, "registry_refs", [])
    if reg_refs:
        print(f"\n[*] ─── Registry References ({len(reg_refs)}) ───")
        print("    (keys/values the driver reads — device name may be loaded here at runtime)")
        for r in reg_refs:
            print(f"    [r] {r}")

    # ── ROP Gadgets Summary ───────────────────────────────────────────────
    if scanner.rop_gadgets and args.verbose:
        total_g = sum(len(v) for v in scanner.rop_gadgets.values())
        useful = {k: v for k, v in scanner.rop_gadgets.items() if v}
        type_summary = ", ".join(f"{k}: {len(v)}" for k, v in
                                 sorted(useful.items(), key=lambda x: -len(x[1])))
        print(f"\n[*] ROP/JOP Gadgets: {total_g} ({type_summary})")
        for gtype in ("privilege-op", "stack-pivot", "memory-write"):
            glist = scanner.rop_gadgets.get(gtype, [])
            if glist:
                print(f"    [{gtype}]:")
                for g in glist[:3]:
                    print(f"      0x{g['va']:X}: {g['asm']}")

    # ── Exploit Chains ────────────────────────────────────────────────────
    if scanner.exploit_chains and args.verbose:
        print(f"\n[{'!' if any(c['severity'] >= Severity.CRITICAL for c in scanner.exploit_chains) else '*'}] "
              f"Exploit Chains: {len(scanner.exploit_chains)} identified")
        for chain in scanner.exploit_chains:
            diff = chain["difficulty"].split(" —")[0]
            print(f"    [{diff}] {chain['name']}")
            for step in chain["steps"][:4]:
                print(f"      {step}")
            if len(chain["steps"]) > 4:
                print(f"      ... +{len(chain['steps'])-4} more steps")
            for e in chain.get("dataflow_edges", []):
                print(f"      [edge] {e['from']} ({e['from_prim']})  "
                      f"--{e['type']}-->  {e['to']} ({e['to_prim']})")

    # ── Weaponizable Chains (default-visible) ─────────────────────────────
    # A chain with at least one typed dataflow edge is *actually* exploitable
    # in-driver — the value the earlier IOCTL produces is the input the
    # later one consumes. This is the part a red teamer needs at a glance.
    weaponizable = [c for c in (scanner.exploit_chains or [])
                    if c.get("dataflow_edges")]
    if weaponizable:
        print(f"\n[!] Weaponizable Chains ({len(weaponizable)}):")
        for c in weaponizable:
            print(f"    [{c['difficulty'].split(' —')[0]}] {c['name']}")
            for e in c["dataflow_edges"][:4]:
                print(f"      {e['from']} ({e['from_prim']})  "
                      f"--{e['type']}-->  {e['to']} ({e['to_prim']})")
            if len(c["dataflow_edges"]) > 4:
                print(f"      ... +{len(c['dataflow_edges'])-4} more edges")

    # ── Taint Paths ───────────────────────────────────────────────────────
    if scanner.taint_paths and args.verbose:
        print(f"\n[!] Inter-procedural Taint Paths: {len(scanner.taint_paths)}")
        for tp in scanner.taint_paths[:5]:
            decoded = decode_ioctl(tp["ioctl"])
            print(f"    {decoded['code']} → {tp['sink']}({tp['tainted_arg']}) "
                  f"@ 0x{tp['sink_addr']:X}  [depth={tp['depth']}]")

    # ── Z3 Solutions ──────────────────────────────────────────────────────
    if scanner.z3_solutions and args.verbose:
        sat_count = sum(1 for s in scanner.z3_solutions if s.get("satisfiable"))
        print(f"\n[!] Z3 Constraint Solver: {sat_count} exploitable path(s) confirmed")
        for sol in scanner.z3_solutions[:5]:
            if sol.get("satisfiable"):
                decoded = decode_ioctl(sol["ioctl"])
                print(f"    {decoded['code']} → {sol['sink']}: SAT")
                if sol.get("trigger_input"):
                    fields = sol["trigger_input"]
                    for off, val in sorted(fields.items()):
                        print(f"      {off} = 0x{val:X}")

    # ── State Machine ─────────────────────────────────────────────────────
    if scanner.attack_sequences and args.verbose:
        print(f"\n[!] Multi-IOCTL Attack Sequences: {len(scanner.attack_sequences)}")
        for seq in scanner.attack_sequences[:5]:
            path_str = " → ".join(decode_ioctl(c)["code"] for c in seq["sequence"])
            prims = ", ".join(seq["primitives"])
            print(f"    {path_str}  [{prims}]")

    # ── Pool tags ─────────────────────────────────────────────────────────
    if args.verbose:
        pool_tags = pe_analyzer.extract_pool_tags(dis)
        if pool_tags:
            print(f"[*] Pool tags ({len(pool_tags)}):")
            for va, tag, fn in pool_tags[:20]:
                print(f"    '{tag}'  at 0x{va:X}  ({fn})")

    # ── Auto-generated YARA rule ──────────────────────────────────────────
    if args.verbose:
        yara_rule = generate_yara_rule(pe_info, scanner, pe_analyzer)
        if yara_rule:
            print(f"\n[*] Auto-generated YARA rule:")
            print(yara_rule)

    # In verbose mode: print every finding with full detail
    if args.verbose:
        print()
        for f in scanner.findings:
            out.finding(f)
        print()

    findings = scanner.findings

    # ── 5. Optional source scan ──────────────────────────────────────────
    if args.source:
        out.info(f"Scanning {len(args.source)} source file(s)...")
        src_scanner = SourceScanner(args.source)
        src_findings = src_scanner.scan()
        if args.verbose:
            for f in src_findings:
                out.finding(f)
        findings.extend(src_findings)

    # ── 7. Select device name for PoCs ───────────────────────────────────
    all_names = pe_analyzer.device_names
    device_name = None

    if args.device:
        device_name = args.device
    else:
        for name in all_names:
            if (name.startswith("\\DosDevices\\") or
                    name.startswith("\\??\\") or
                    name.startswith("\\GLOBAL??\\")):
                device_name = name
                break
        if not device_name and all_names:
            device_name = all_names[0]

    if device_name:
        if args.verbose:
            out.info(f"Using device path for PoCs: {device_name}")
    else:
        if args.verbose:
            out.warn("Device name not found. Use --device NAME to set it manually.")

    # ── 9. Generate C PoCs ───────────────────────────────────────────────
    poc_gen = PoCGenerator(device_name=device_name, ioctl_codes=scanner.ioctl_codes)
    pocs = poc_gen.generate_all(findings)

    if pocs and args.verbose:
        out.info(f"Generating {len(pocs)} PoC exploit(s) in C...")

    # ── 10. Save & compile PoCs ──────────────────────────────────────────
    do_compile = args.compile or (args.save_pocs and check_gcc())
    if args.save_pocs and pocs:
        os.makedirs(args.output_dir, exist_ok=True)
        has_gcc = check_gcc()
        if do_compile and not has_gcc:
            out.warn("gcc/x86_64-w64-mingw32-gcc not found — saving .c only. "
                     "Install MinGW-w64 to auto-compile.")

        for fname, content in pocs.items():
            c_path = os.path.join(args.output_dir, fname)
            with open(c_path, "w") as f:
                f.write(content)
            out.good(f"Saved: {c_path}")

            if do_compile and has_gcc:
                exe_path = compile_poc(c_path)
                if exe_path:
                    out.good(f"Compiled: {exe_path}")
                else:
                    out.warn(f"Compile failed for {fname} — .c saved, fix manually")
    elif pocs and not args.save_pocs and args.verbose:
        for fname in pocs:
            print(f"    {fname}")
        print(f"  {out.DIM}(Use --save-pocs to write PoC files to disk){out.RESET}")

    # ── 11. Verbose: entry point disassembly ─────────────────────────────
    if args.verbose:
        print(f"\n[*] Entry point disassembly (first 50 instructions):\n")
        ep_addr, ep_bytes = pe_analyzer.get_entry_point_bytes(count=512)
        insns = dis.disassemble_range(ep_bytes, ep_addr, max_insns=50)
        for insn in insns:
            print(f"  0x{insn.address:X}:  {insn.mnemonic:8s} {insn.op_str}")
        print()

    # ── JSON export ───────────────────────────────────────────────────────
    if args.json:
        chains_serializable = []
        for c in (scanner.exploit_chains or []):
            chains_serializable.append({
                "name":     c.get("name", ""),
                "severity": c.get("severity").name
                            if hasattr(c.get("severity"), "name") else str(c.get("severity")),
                "steps":    list(c.get("steps", [])),
                "dataflow_edges": list(c.get("dataflow_edges", [])),
            })
        export_json(pe_info, scanner, args.json,
                    device_names=pe_analyzer.device_names,
                    exploit_chains=chains_serializable)
        out.info(f"JSON report written: {args.json}")

    # ── IDAPython annotation script ───────────────────────────────────────
    if args.ida:
        script = generate_ida_script(pe_info, scanner, pe_analyzer)
        with open(args.ida, "w", encoding="utf-8") as ida_fp:
            ida_fp.write(script)
        out.info(f"IDAPython script written: {args.ida}  "
                 f"(File→Script file inside IDA)")

    # ── Fuzzer harness generation ─────────────────────────────────────────
    if args.fuzzer and scanner.ioctl_codes:
        dev = (args.device or
               (pe_analyzer.device_names[0] if pe_analyzer.device_names else "\\\\.\\Unknown"))
        written = generate_fuzzer_harness(
            dev, scanner.ioctl_codes, scanner.ioctl_purposes, args.output_dir)
        for p in written:
            out.info(f"Harness written: {p}")

    # ── IOCTL tracer generation ───────────────────────────────────────────
    if args.tracer:
        dev = (args.device or
               (pe_analyzer.device_names[0] if pe_analyzer.device_names else "\\\\.\\Unknown"))
        tracer_paths = generate_ioctl_tracer(
            dev, scanner.ioctl_codes, scanner.ioctl_purposes,
            scanner.ioctl_behaviors, scanner.ioctl_structs, args.output_dir)
        for p in tracer_paths:
            out.good(f"Tracer written: {p}")
        print(f"\n  IOCTL Runtime Tracer:")
        print(f"    Compile and run on Windows as Administrator.")
        print(f"    Probes each IOCTL to discover what it does at runtime.")
        print(f"    Use when static analysis shows driver as 'safe' but")
        print(f"    you suspect hidden capabilities.\n")

    # ── Check script generation ────────────────────────────────────────────
    if args.check_script:
        script_path = generate_check_script(
            pe_info, scanner, pe_analyzer, args.output_dir)
        out.good(f"PowerShell check script written: {script_path}")
        print(f"\n  Copy to Windows and run as Administrator:")
        print(f"    .\\{os.path.basename(script_path)}")
        print(f"    .\\{os.path.basename(script_path)} -Load           # load the driver")
        print(f"    .\\{os.path.basename(script_path)} -Unload         # unload the driver")
        print(f"    .\\{os.path.basename(script_path)} -Detailed       # include event log")
        print(f"    .\\{os.path.basename(script_path)} -DriverPath C:\\path\\to\\{os.path.basename(pe_info['filepath'])}")
        print()

    # ── Summary & exit code ───────────────────────────────────────────────
    if args.verbose:
        out.summary(findings)

    # ── Attack surface score ──────────────────────────────────────────────
    if args.verbose:
        print(f"\n[*] Attack Surface Score: {scanner.attack_score}/100 ({scanner.attack_risk})")

    # ── Final load verdict (clear yes/no for Windows loader) ──────────────
    if args.verbose:
        load_lf = next((f for f in scanner.findings
                        if "Load compatibility" in (f.title or "")), None)
        if load_lf:
            det = load_lf.details or {}
            can = det.get("can_load", "Unknown")
            blockers_n = len(det.get("blockers", []))
            if can == "True":
                out.good("Windows Load Verdict: WILL LOAD on a default modern Windows install")
            elif blockers_n:
                out.warn(f"Windows Load Verdict: BLOCKED — {blockers_n} loader check(s) fail "
                         f"(see LOAD VERDICT section above)")
            else:
                out.info("Windows Load Verdict: UNKNOWN")

    max_sev = max((f.severity for f in findings), default=Severity.INFO)
    if max_sev >= Severity.CRITICAL:
        return 2
    elif max_sev >= Severity.HIGH:
        return 1
    return 0
