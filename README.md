# drivertool

**A static-analysis & exploitation-triage toolkit for Windows kernel drivers.**

Answers two questions about any `.sys` file:
1. **Will this driver actually load on Windows?** full Authenticode + WDAC + HVCI policy modelling.
2. **What can it do, and how would I exploit it?** IOCTL discovery, taint analysis, exploit-primitive classification, PoC generation.

Built for BYOVD hunters, driver triagers, kernel reverse engineers, and security researchers who want a deep static report on a driver in seconds.

---

## What it tells you

For every driver you point it at:

### Load verdict

A per-Windows-configuration matrix not a single yes/no:

```
─── LOAD VERDICT ───
  Default Win10/11         : WILL LOAD
  Secure Boot + DSE        : WILL LOAD
  HVCI / Memory Integrity  : WILL NOT LOAD
      • FORCE_INTEGRITY flag not set (HVCI requires it)
      • W+X section present (HVCI forbids RWX)
  Test-signing mode        : WILL LOAD
  S Mode                   : WILL NOT LOAD
      • No WHQL attestation EKU
```

Driven by full **Authenticode** verification:
- PKCS#7 signature crypto verify (RSA-PKCS1v15 / ECDSA)
- Authenticode PE-hash recomputation (catches post-signing tampering)
- Nested signature parsing (SHA-1 + SHA-256 dual-sign)
- Counter-signature & RFC 3161 timestamp binding check
- Live Microsoft trust lists (`authroot.stl`, `disallowedcert.stl`, WDAC vulnerable-driver block list)
- Chain-anchor classification against kernel-trusted roots
- Grandfathering: SHA-1 cutoff (2015-07-29), cross-sign cutoff (2021-07-01), legacy-TSA acceptance, expired-with-timestamp
- EKU propagation, kernel-signing EKUs (WHQL attestation, MS System Component, WSVT)
- Catalog-signing inference for OS-shipped drivers
- HVCI prerequisite checks (page hashes, EV cert, WHQL EKU)

### IOCTL surface

```
[*] Detected IOCTL codes (32):
    0x7299C008  @0x140004320  (BUFFERED, FILE_READ_WRITE)  → callback removal
                [!!CB REMOVE] [!!DSE RESOLVE] [!!PPL BYPASS] [!!TOKEN STEAL]
                bugs=arbitrary-rw,callback-tamper,toctou-attach,token-theft
                [UNGATED-sink] [shares process-kill-site with 0x7299C00C]
```

Per IOCTL: handler VA, decoded method/access, purpose, exploit primitives, bug classes, gate state, shared-site convergence, hash-dispatch reversal, FSCTL slot tagging.

Discovery via **three independent paths**: dispatch-table walk, WDF emulator, brute-force scan. Plus hash-based dispatch reversal (FNV/djb2/CRC32/sdbm) for anti-RE drivers.

### Exploit primitives + bug classes

For each handler:
- **Primitives**: `process-kill`, `token-steal`, `ppl-bypass`, `dse-disable`, `arb-write`, `arb-read`, `physical-rw`, `msr-rw`, `callback-removal`, `etw-disable`, `process-attach`, `thread-inject`, `process-control`
- **Bug classes**: `arbitrary-rw`, `missing-probe`, `int-overflow-alloc`, `double-fetch`, `toctou-attach`, `dse-bypass`, `callback-tamper`, `token-theft`, `process-kill`, `length-bounded`, `length-unbounded`

Classifications gated by a real analysis stack:
- **Per-handler taint** (forward, memory, interprocedural via cached function summaries)
- **Backward slicing** at every dangerous call site → arg provenance (`imm` / `mem_input_buffer+offset` / `api_return` / etc)
- **Constant propagation** + bounds-check inference
- **Basic-block CFG** + path-sensitive gate detection (`every path passes through SeAccessCheck?`)
- **Shared call-site dedup** + thin-wrapper detection (one primitive, multiple entry points)
- **EPROCESS semantic field map** Token / Protection / SignatureLevel / ImageFilePointer write classification across Win8.1..Win11
- **Tightened double-fetch detector** (4-gate: same offset + check-between + no capture API + flow-to-sink)

### Device-name recovery

Names recovered via 13+ independent strategies *plus* a Unicorn-emulated `DriverEntry` sandbox for runtime-built names:
- IAT disasm trace · XOR-decoded UNICODE_STRINGs · XMM stack-spill emulator · stack-packed immediates · `.data` initializers · `RtlStringCbPrintfW` format templates · registry-service paths · `wcscat` composition · GUID structures · `POBJECT_ATTRIBUTES.ObjectName` · dynamic prefix templates · symlink-pair inference · Unicorn DriverEntry emulation

Plus minifilter port detection (`FltCreateCommunicationPort`).

### Generated artifacts

| Flag | What you get |
|---|---|
| `--save-pocs` | Compilable C `DeviceIoControl` PoCs per IOCTL |
| `--compile` | Auto-compile PoCs to `.exe` (requires MinGW-w64) |
| `--fuzzer` | Python + C IOCTL fuzzing harness |
| `--tracer` | Runtime IOCTL behaviour tracer (probes each IOCTL on a live system) |
| `--check-script` | PowerShell driver-status checker (load/unload/event-log inspect) |
| `--ida FILE` | IDAPython annotation script (severity-prefixed handler names, struct definitions, primitive call-site comments, arg provenance) |
| `--json FILE` | Full structured analysis output |

---

## Quick start

```bash
# Analyze a driver
python3 DrvEye.py path/to/driver.sys

# Verbose + save PoCs
python3 DrvEye.py driver.sys -v --save-pocs

# Generate IDAPython annotation script for instant RE acceleration
python3 DrvEye.py driver.sys --ida driver_annotations.py

# Refresh Microsoft policy data + LOLDrivers intel before scanning
python3 DrvEye.py --live-check --loldrivers driver.sys

# Batch multiple drivers in one invocation
python3 DrvEye.py *.sys

# Full power: live data + IDA script + JSON + PoCs + fuzzer
python3 DrvEye.py driver.sys --live-check --loldrivers \
    --json report.json --ida driver.idapy --save-pocs --fuzzer
```

---

## Installation

### Requirements

- **Python 3.9+**
- **pefile** PE parsing
- **capstone** x86-64 disassembly
- **cryptography** Authenticode RSA/ECDSA verification
- **unicorn** *(optional)* full-CPU emulation for hardened device-name extraction
- **yara-python** *(optional)* for `--save-pocs` / `--check-script` enrichment

```bash
pip install pefile capstone cryptography unicorn yara-python
```

### Quick install

```bash
git clone https://github.com/<your-username>/drivertool.git
cd drivertool
pip install -r requirements.txt    # if a requirements.txt is provided
python3 DrvEye.py --help
```

> **Note**: Unicorn is optional. Without it the static device-name recovery still produces results you just lose the emulator fallback for hardened drivers.

---

## CLI reference

```text
usage: DrvEye.py [-h] [--source SOURCE [SOURCE ...]] [--output-dir DIR]
                      [--save-pocs] [--verbose] [--no-color] [--compile]
                      [--device NAME] [--json FILE] [--output FILE]
                      [--fuzzer] [--check-script] [--tracer] [--ida FILE]
                      [--live-check] [--loldrivers] [--no-live-policy]
                      [drivers ...]
```

| Flag | Description |
|---|---|
| `drivers` | One or more `.sys` paths to analyze. |
| `--source FILES` | Optional C/C++ source files to scan alongside the binary. |
| `--output-dir DIR` | Directory for generated artifacts (default: `pocs_output`). |
| `--save-pocs` | Write generated PoC scripts to disk. |
| `--verbose, -v` | Show all findings + entry-point disassembly + extra detail. |
| `--no-color` | Disable ANSI color (useful when piping). |
| `--compile` | Auto-compile generated PoC `.c` files via MinGW-w64. |
| `--device NAME` | Override device name for PoCs (`MyDriver` → opens `\\.\MyDriver`). |
| `--json FILE` | Write full analysis results as structured JSON. |
| `--output FILE, -o` | Redirect human-readable report to file (auto-disables color). |
| `--fuzzer` | Generate Python + C IOCTL fuzzing harnesses. |
| `--check-script` | Generate a PowerShell script to load/unload/check the driver on Windows. |
| `--tracer` | Generate a runtime IOCTL tracer (probes each IOCTL on a live target). |
| `--ida FILE` | Emit an IDAPython script that annotates the driver in IDA Pro. |
| `--live-check` | Sync MS kernel-trust + cert-revocation + WDAC vulnerable-driver lists from Windows Update (`authroot.stl`, `disallowedcert.stl`, `SiPolicy_Enforced.p7b`). |
| `--loldrivers` | Extend the local known-vulnerable-driver database with feeds from LOLDrivers, Microsoft, MalwareBazaar, Hybrid Analysis, and HEVD. |
| `--no-live-policy` | Ignore the cached live policy data (use built-in `KERNEL_TRUSTED_ROOTS` snapshot only). |

---

## Live policy data

By default, the tool falls back to ~20 hardcoded Microsoft root-CA thumbprints. With `--live-check` it pulls the actual current data Windows uses:

- **`authroot.stl`** ~988 trusted root CA thumbprints
- **`disallowedcert.stl`** explicitly distrusted cert thumbprints
- **`SiPolicy_Enforced.p7b`** Microsoft's WDAC vulnerable-driver block list (~889 SHA-1 + ~870 SHA-256 hashes)

`--loldrivers` adds external community/research feeds (LOLDrivers, MalwareBazaar, Hybrid Analysis, HEVD) into a unified local index.

Caches live under `~/.cache/drivertool/` and persist between runs. Run weekly to stay current.

```bash
# One-time refresh ~3-5 seconds, downloads ~350 KB total
python3 DrvEye.py --live-check --loldrivers driver.sys
```

After the refresh, every subsequent run uses the cached data automatically no need to re-pass the flags.

---

## Output sections

1. **PE summary** SHA-256, imphash, architecture, mitigations, version info
2. **Authenticode signature** status, primary + nested digest, timestamp, anchor, HVCI prereqs, full chain
3. **Load verdict** per-config matrix + blockers + passes + confidence
4. **Imports** dangerous functions called by the driver
5. **IOCTL codes** every recovered IOCTL with handler VA, purpose, primitives, bug classes, convergence chips
6. **Exploit primitives** per-IOCTL primitive list with shared-site VAs
7. **Device access security** IoCreateDeviceSecure status, SDDL, exclusivity, symlink reachability, issues
8. **Device names & symbolic links** all recovered device paths
9. **Minifilter ports** `FltCreateCommunicationPort` entries (when present)
10. **Registry references** keys/values the driver reads
11. **ROP gadgets, exploit chains, taint paths, Z3 solutions** extra detail with `-v`

With `--verbose`, you also get IRP-handler behavior breakdowns, per-IOCTL recovered input structs, entry-point disassembly, and bug-class taxonomy explanations.

---

## Disclaimer & responsible use

This tool is built for:

- Legitimate security research, red-team / blue-team operations
- Driver development and pre-release auditing
- BYOVD investigation in a defensive context
- Reverse engineering education and CTF challenges

It is **not** a malware authoring kit. The PoC / fuzzer / tracer artifacts it generates are stub C/PowerShell harnesses they require a vulnerable driver on the target system and are intended for analysts confirming reproducibility on systems they own or have explicit authorization to test.

You are responsible for ensuring you have authorization to analyze any driver, run any generated PoC, or load any binary onto any system. The authors disclaim liability for misuse.

If you find a vulnerability in a vendor driver, please follow responsible disclosure the project authors actively support that path.

---

## License

MIT see [LICENSE](LICENSE).


