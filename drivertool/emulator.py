"""Full-CPU emulation of a Windows driver's ``DriverEntry`` routine to
recover device/symlink names that escape static analysis.

Many hardened drivers reconstruct their device name at runtime — XOR
chains too long for our static tracer, multi-part ``wcscat`` assembly
of a registry-fetched prefix, arithmetic sequences, or small custom
ciphers. Rather than implement every possible obfuscation pattern
one-by-one, run the code in a Unicorn x86-64 sandbox and collect
whatever ``UNICODE_STRING`` buffers land in memory at the end.

API stubs cover the kernel primitives driver-entry routines rely on
for name registration:

  IoCreateDevice, IoCreateDeviceSecure, IoCreateSymbolicLink,
  RtlInitUnicodeString, RtlCopyUnicodeString, RtlAppendUnicodeToString,
  ExAllocatePool*, RtlStringCchCopyW/RtlStringCbCopyW,
  RtlStringCchPrintfW, MmGetSystemRoutineAddress, ...

Unresolved calls return STATUS_SUCCESS (0) and continue. Memory-access
violations and unmapped fetches are silently skipped — we trade
completeness for robustness so we never crash the outer scan.

Unicorn is an optional dependency; if it is not installed this module
exposes a no-op ``extract_emulated_device_names()`` that returns ``[]``.
"""
from __future__ import annotations

from typing import List, Optional, Set, Tuple

import logging

logger = logging.getLogger(__name__)

try:
    from unicorn import (
        Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32,
        UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_UNMAPPED,
        UcError,
    )
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP,
        UC_X86_REG_RIP, UC_X86_REG_RBP,
        UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP,
    )
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


# ──────────────────────────────────────────────────────────────────────────
# Layout of the sandbox address space
# ──────────────────────────────────────────────────────────────────────────

STACK_BASE   = 0x7FFF_0000_0000
STACK_SIZE   = 0x0010_0000              # 1 MiB
HEAP_BASE    = 0x6FFF_0000_0000
HEAP_SIZE    = 0x0400_0000              # 64 MiB (plenty for pool alloc)
IAT_STUB_BASE = 0x5FFF_0000_0000        # each imported API → unique stub addr
IAT_STUB_STRIDE = 0x10
INTERESTING_PREFIXES = (
    "\\Device\\", "\\DosDevices\\", "\\??\\", "\\GLOBAL??\\",
)


# ──────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────

def extract_emulated_device_names(pe_analyzer, max_insns: int = 100_000,
                                   ) -> List[str]:
    """Emulate DriverEntry in a Unicorn sandbox and return every
    ``\\Device\\*`` / ``\\DosDevices\\*`` / ``\\??\\*`` / ``\\GLOBAL??\\*``
    UNICODE_STRING observed in memory at end of execution.

    Returns an empty list when Unicorn is not installed or the
    emulation fails before producing any names.
    """
    if not UNICORN_AVAILABLE:
        return []
    try:
        emu = _DriverEmulator(pe_analyzer)
        emu.run(max_insns=max_insns)
        return sorted(emu.found_names)
    except Exception:
        logger.debug("Emulation failed", exc_info=True)
        return []


# ──────────────────────────────────────────────────────────────────────────
# Emulator implementation
# ──────────────────────────────────────────────────────────────────────────

class _DriverEmulator:
    """One-shot DriverEntry emulator. Not reusable — construct fresh
    for each driver. Tracks captured strings in ``self.found_names``."""

    def __init__(self, pe_analyzer):
        self.pe = pe_analyzer
        self._is_64bit = pe_analyzer.is_64bit
        mode = UC_MODE_64 if self._is_64bit else UC_MODE_32
        self.uc: Uc = Uc(UC_ARCH_X86, mode)
        self.found_names: Set[str] = set()

        self.image_base = pe_analyzer.pe.OPTIONAL_HEADER.ImageBase
        self.image_size = pe_analyzer.pe.OPTIONAL_HEADER.SizeOfImage
        # Round up to page boundary
        self.image_size = (self.image_size + 0xFFF) & ~0xFFF

        # Map PE image in virtual layout — copy PE headers + each section's
        # raw bytes at its VA offset, not the file-offset-ordered raw[:].
        self.uc.mem_map(self.image_base, self.image_size)
        headers_size = pe_analyzer.pe.OPTIONAL_HEADER.SizeOfHeaders
        self.uc.mem_write(self.image_base,
                          pe_analyzer.raw[:headers_size])
        for section in pe_analyzer.pe.sections:
            va = self.image_base + section.VirtualAddress
            raw = section.get_data()
            if raw and va >= self.image_base and va < self.image_base + self.image_size:
                try:
                    self.uc.mem_write(va, raw[:section.Misc_VirtualSize or len(raw)])
                except UcError:
                    pass

        # Stack
        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        rsp = STACK_BASE + STACK_SIZE - 0x1000
        sp_reg = UC_X86_REG_RSP if self._is_64bit else UC_X86_REG_ESP
        bp_reg = UC_X86_REG_RBP if self._is_64bit else UC_X86_REG_EBP
        self.uc.reg_write(sp_reg, rsp)
        self.uc.reg_write(bp_reg, rsp)

        # Heap — used for any "allocated" buffer we hand out
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE)
        self.heap_cursor = HEAP_BASE

        # Build IAT stub page: each unique IAT slot gets a dedicated
        # instruction address we trap on.
        self.iat_to_stub: dict = {}
        self.stub_to_api: dict = {}
        self._setup_iat_stubs()

        # Hook every instruction to intercept stub fetches + walk RIP
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        # Silence unmapped accesses instead of aborting
        self.uc.hook_add(
            UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_INVALID,
            self._mem_fault_hook,
        )

        # Driver-entry call convention:
        #   RCX = PDRIVER_OBJECT, RDX = PUNICODE_STRING registry path.
        # Synthesize plausible pointers so drivers that deref them don't
        # fault out immediately.
        self.driver_object = self._alloc(0x400)
        self.registry_path_us = self._alloc_unicode_string(
            "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Drv")
        if self._is_64bit:
            self.uc.reg_write(UC_X86_REG_RCX, self.driver_object)
            self.uc.reg_write(UC_X86_REG_RDX, self.registry_path_us)
        else:
            # x86 stdcall: args pushed right-to-left
            self._push32(self.registry_path_us)
            self._push32(self.driver_object)

        self.entry_va = self.image_base + pe_analyzer.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self._insns_run = 0
        self._max_insns = 100_000

        # Also push a sentinel return address so a RET from DriverEntry
        # lands on our sentinel page (we intercept and stop there).
        self.sentinel_ret = IAT_STUB_BASE - 0x1000
        self.uc.mem_map(self.sentinel_ret & ~0xFFF, 0x1000)
        # push sentinel return address
        if self._is_64bit:
            sp = self.uc.reg_read(UC_X86_REG_RSP) - 8
            self.uc.mem_write(sp, self.sentinel_ret.to_bytes(8, "little"))
            self.uc.reg_write(UC_X86_REG_RSP, sp)
        else:
            self._push32(self.sentinel_ret)

    # ── Heap helpers ────────────────────────────────────────────────────

    def _alloc(self, size: int) -> int:
        addr = self.heap_cursor
        size = (size + 0x1F) & ~0x1F
        if addr + size > HEAP_BASE + HEAP_SIZE:
            return HEAP_BASE  # reuse from start; not ideal but defensive
        self.heap_cursor = addr + size
        # Zero the allocation
        self.uc.mem_write(addr, b"\x00" * size)
        return addr

    def _alloc_unicode_string(self, s: str) -> int:
        """Allocate a UNICODE_STRING + backing UTF-16 buffer. Returns US ptr."""
        buf = s.encode("utf-16-le")
        buf_addr = self._alloc(len(buf) + 2)
        self.uc.mem_write(buf_addr, buf + b"\x00\x00")
        if self._is_64bit:
            us = self._alloc(16)
            length = len(buf)
            # USHORT Length, USHORT MaximumLength, PAD, PWSTR Buffer
            self.uc.mem_write(us, length.to_bytes(2, "little")
                             + (length + 2).to_bytes(2, "little")
                             + b"\x00" * 4
                             + buf_addr.to_bytes(8, "little"))
            return us
        else:
            us = self._alloc(8)
            length = len(buf)
            # USHORT Length, USHORT MaximumLength, PWSTR Buffer
            self.uc.mem_write(us, length.to_bytes(2, "little")
                             + (length + 2).to_bytes(2, "little")
                             + buf_addr.to_bytes(4, "little"))
            return us

    def _push32(self, value: int):
        """Push a 32-bit value onto the x86 stack."""
        sp = self.uc.reg_read(UC_X86_REG_ESP) - 4
        self.uc.mem_write(sp, (value & 0xFFFFFFFF).to_bytes(4, "little"))
        self.uc.reg_write(UC_X86_REG_ESP, sp)

    # ── IAT stubbing ────────────────────────────────────────────────────

    def _setup_iat_stubs(self):
        # Map a dedicated executable page for stubs
        self.uc.mem_map(IAT_STUB_BASE, 0x10000)
        # Fill with 0xC3 (RET) so any accidental fall-through just returns
        self.uc.mem_write(IAT_STUB_BASE, b"\xC3" * 0x10000)

        cursor = IAT_STUB_BASE
        for iat_va, name in self.pe.iat_map.items():
            self.iat_to_stub[iat_va] = cursor
            self.stub_to_api[cursor] = name
            # Rewrite the IAT entry in the emulated image so indirect
            # "call qword ptr [rip+iat]" lands on our stub.
            try:
                self.uc.mem_write(iat_va, cursor.to_bytes(8, "little"))
            except UcError:
                pass
            cursor += IAT_STUB_STRIDE
            if cursor >= IAT_STUB_BASE + 0x10000:
                break

    # ── Hook handlers ───────────────────────────────────────────────────

    def _mem_fault_hook(self, uc, access, address, size, value, _):
        """On any unmapped access, map a page of zeroes and continue.
        This lets us survive dereferences of DRIVER_OBJECT fields and
        other kernel-structure poking we don't emulate."""
        try:
            page = address & ~0xFFF
            # Don't map into image/stack/heap/stub ranges (already mapped)
            if self._is_already_mapped(page):
                return True
            uc.mem_map(page, 0x1000)
            uc.mem_write(page, b"\x00" * 0x1000)
        except UcError:
            pass
        return True

    def _is_already_mapped(self, page: int) -> bool:
        regions = [
            (self.image_base, self.image_base + self.image_size),
            (STACK_BASE, STACK_BASE + STACK_SIZE),
            (HEAP_BASE, HEAP_BASE + HEAP_SIZE),
            (IAT_STUB_BASE, IAT_STUB_BASE + 0x10000),
            (self.sentinel_ret & ~0xFFF,
             (self.sentinel_ret & ~0xFFF) + 0x1000),
        ]
        return any(lo <= page < hi for lo, hi in regions)

    def _code_hook(self, uc, address, size, _):
        self._insns_run += 1
        if self._insns_run >= self._max_insns:
            uc.emu_stop()
            return

        # Sentinel return → emulation complete
        if address == self.sentinel_ret:
            uc.emu_stop()
            return

        # Stub address → simulate API
        if address in self.stub_to_api:
            api = self.stub_to_api[address]
            self._handle_api(api)
            # Fake a RET
            if self._is_64bit:
                rsp = uc.reg_read(UC_X86_REG_RSP)
                try:
                    ret_addr = int.from_bytes(uc.mem_read(rsp, 8), "little")
                except UcError:
                    uc.emu_stop()
                    return
                uc.reg_write(UC_X86_REG_RSP, rsp + 8)
                uc.reg_write(UC_X86_REG_RIP, ret_addr)
            else:
                esp = uc.reg_read(UC_X86_REG_ESP)
                try:
                    ret_addr = int.from_bytes(uc.mem_read(esp, 4), "little")
                except UcError:
                    uc.emu_stop()
                    return
                uc.reg_write(UC_X86_REG_ESP, esp + 4)
                uc.reg_write(UC_X86_REG_EIP, ret_addr)

    # ── API stubs ───────────────────────────────────────────────────────

    def _handle_api(self, api: str):
        """Intercept a kernel API call. Record any UNICODE_STRING args
        that look like device/symlink names and populate the
        appropriate out parameters so the driver's own code proceeds."""
        if self._is_64bit:
            rcx = self.uc.reg_read(UC_X86_REG_RCX)
            rdx = self.uc.reg_read(UC_X86_REG_RDX)
            r8 = self.uc.reg_read(UC_X86_REG_R8)
            r9 = self.uc.reg_read(UC_X86_REG_R9)
        else:
            # x86 stdcall: read args from stack (esp + 4 retaddr + args)
            esp = self.uc.reg_read(UC_X86_REG_ESP)
            rcx = self._read_stack32(esp + 4)
            rdx = self._read_stack32(esp + 8)
            r8 = self._read_stack32(esp + 12)
            r9 = self._read_stack32(esp + 16)

        # Every API returns 0 (STATUS_SUCCESS / NULL) by default
        ret = 0

        if api in ("IoCreateDevice", "IoCreateDeviceSecure",
                   "WdmlibIoCreateDeviceSecure"):
            # IoCreateDevice(DriverObject, Extra, DeviceName, DeviceType,
            #                Characteristics, Exclusive, DeviceObject*)
            # DeviceName is in R8
            self._capture_unicode_string(r8)
            # Write a fake PDEVICE_OBJECT into the out param (stack arg 7).
            # On x64 that's at [RSP + 0x30] (shadow + args).
            dev_out = self._read_stack_arg(6)
            if dev_out:
                fake_dev = self._alloc(0x200)
                self._safe_write_ptr(dev_out, fake_dev)
            ret = 0

        elif api in ("IoCreateSymbolicLink",):
            # IoCreateSymbolicLink(SymbolicLinkName, DeviceName)
            self._capture_unicode_string(rcx)
            self._capture_unicode_string(rdx)

        elif api in ("IoCreateUnprotectedSymbolicLink",):
            self._capture_unicode_string(rcx)
            self._capture_unicode_string(rdx)

        elif api in ("ZwCreateSymbolicLinkObject",
                     "NtCreateSymbolicLinkObject"):
            # (Handle*, Access, ObjectAttributes, LinkTarget)
            # LinkTarget is a UNICODE_STRING in R9; OA.ObjectName in R8.
            self._capture_unicode_string(r9)
            self._capture_object_attributes(r8)

        elif api in ("IoRegisterDeviceInterface",):
            # (PhysicalDeviceObject, InterfaceClassGuid, ReferenceString,
            #  SymbolicLinkName*)
            # ReferenceString is UNICODE_STRING at R8
            self._capture_unicode_string(r8)

        elif api in ("RtlInitUnicodeString",):
            # (DestString, SourceString PCWSTR)
            self._write_rtl_init_unicode_string(rcx, rdx)
            # Also capture in case this is a device name being set up
            self._capture_wide_string_at(rdx)

        elif api in ("RtlCopyUnicodeString",):
            # (Destination, Source)
            self._capture_unicode_string(rdx)

        elif api in ("RtlAppendUnicodeToString",
                     "RtlAppendUnicodeStringToString"):
            # Accumulates a string; we re-scan memory at end of run.
            self._capture_unicode_string(rcx)

        elif api in ("FltCreateCommunicationPort",):
            # (FilterHandle, ServerPort*, ObjectAttributes, ...)
            self._capture_object_attributes(r8)

        elif api in ("ExAllocatePoolWithTag", "ExAllocatePoolWithQuotaTag",
                     "ExAllocatePool2", "ExAllocatePool3",
                     "ExAllocatePoolWithQuota", "ExAllocatePool",
                     "ExAllocatePoolZero"):
            # Return a real heap block the driver can write into
            size = rdx if api != "ExAllocatePool2" else r8
            ret = self._alloc(min(int(size) if size else 0x100, 0x10000))

        elif api in ("RtlStringCchCopyW", "RtlStringCbCopyW",
                     "wcscpy", "wcscpy_s", "RtlStringCchCopyExW"):
            # (Dest, Size, Src) — Dest is RCX, Src is RDX or R8
            src = rdx if api in ("RtlStringCchCopyW", "RtlStringCbCopyW",
                                  "wcscpy") else r8
            self._capture_wide_string_at(src)

        elif api in ("RtlStringCchCatW", "RtlStringCbCatW", "wcscat"):
            self._capture_wide_string_at(rcx)  # dest after cat
            self._capture_wide_string_at(rdx)

        elif api in ("RtlStringCchPrintfW", "RtlStringCbPrintfW",
                     "swprintf", "swprintf_s", "_snwprintf"):
            # (Dest, Count, Format, ...) — we can't evaluate %-substitutions
            # but the format string itself may contain the device prefix.
            self._capture_wide_string_at(r8)

        elif api in ("MmGetSystemRoutineAddress",):
            # Return a benign non-zero so driver treats call as success
            ret = self._alloc(0x20)

        elif api in ("ObReferenceObjectByName",
                     "ObReferenceObjectByHandle",):
            # (ObjectName, ...) for first variant
            self._capture_unicode_string(rcx)

        # Leave default ret=0 for everything else
        ret_reg = UC_X86_REG_RAX if self._is_64bit else UC_X86_REG_EAX
        self.uc.reg_write(ret_reg, ret)

    # ── String capture helpers ──────────────────────────────────────────

    def _read_mem(self, addr: int, size: int) -> Optional[bytes]:
        try:
            return bytes(self.uc.mem_read(addr, size))
        except UcError:
            return None

    def _read_stack_arg(self, idx: int) -> Optional[int]:
        """Stack arg N (0-indexed, after the 4 register args)."""
        # On x64, args 5+ start at [RSP + 0x28] (shadow 0x20 + ret 0x08)
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        off = 0x28 + idx * 8
        data = self._read_mem(rsp + off, 8)
        if not data:
            return None
        return int.from_bytes(data, "little")

    def _safe_write_ptr(self, addr: int, value: int):
        try:
            width = 8 if self._is_64bit else 4
            self.uc.mem_write(addr, value.to_bytes(width, "little"))
        except UcError:
            pass

    def _read_stack32(self, addr: int) -> Optional[int]:
        data = self._read_mem(addr, 4)
        if not data:
            return None
        return int.from_bytes(data, "little")

    def _capture_unicode_string(self, us_ptr: int):
        """Read a UNICODE_STRING from memory and stash the buffer."""
        if not us_ptr:
            return
        width = 16 if self._is_64bit else 8
        data = self._read_mem(us_ptr, width)
        if not data or len(data) < width:
            return
        length = int.from_bytes(data[0:2], "little")
        max_len = int.from_bytes(data[2:4], "little")
        ptr_off = 8 if self._is_64bit else 4
        ptr_len = 8 if self._is_64bit else 4
        buf_ptr = int.from_bytes(data[ptr_off:ptr_off + ptr_len], "little")
        if not (0 < length <= 2048) or not buf_ptr:
            return
        buf = self._read_mem(buf_ptr, length)
        if not buf:
            return
        try:
            s = buf.decode("utf-16-le", errors="ignore").rstrip("\x00")
        except Exception:
            return
        if s and any(s.startswith(p) for p in INTERESTING_PREFIXES):
            self.found_names.add(s)

    def _capture_object_attributes(self, oa_ptr: int):
        """OBJECT_ATTRIBUTES.ObjectName is at offset 0x10 (x64) / 0x08 (x86)."""
        if not oa_ptr:
            return
        name_off = 0x10 if self._is_64bit else 0x08
        ptr_len = 8 if self._is_64bit else 4
        name_ptr_bytes = self._read_mem(oa_ptr + name_off, ptr_len)
        if not name_ptr_bytes:
            return
        name_ptr = int.from_bytes(name_ptr_bytes, "little")
        self._capture_unicode_string(name_ptr)

    def _capture_wide_string_at(self, buf_ptr: int, max_bytes: int = 4096):
        """Read a NUL-terminated UTF-16 string from memory."""
        if not buf_ptr:
            return
        data = self._read_mem(buf_ptr, max_bytes)
        if not data:
            return
        # Find the UTF-16 NUL terminator (two consecutive zero bytes at even off)
        end = len(data)
        for i in range(0, len(data) - 1, 2):
            if data[i] == 0 and data[i + 1] == 0:
                end = i
                break
        try:
            s = data[:end].decode("utf-16-le", errors="ignore")
        except Exception:
            return
        if s and any(s.startswith(p) for p in INTERESTING_PREFIXES):
            self.found_names.add(s)

    def _write_rtl_init_unicode_string(self, dst_us: int, src_wstr: int):
        """Emulate RtlInitUnicodeString(Dest, Src) so subsequent reads of
        Dest's buffer land on the real source bytes."""
        if not dst_us or not src_wstr:
            return
        # Measure src length up to NUL
        data = self._read_mem(src_wstr, 4096)
        if not data:
            return
        length = 0
        for i in range(0, len(data) - 1, 2):
            if data[i] == 0 and data[i + 1] == 0:
                length = i
                break
        try:
            self.uc.mem_write(
                dst_us,
                length.to_bytes(2, "little")
                + (length + 2).to_bytes(2, "little")
                + b"\x00" * 4
                + src_wstr.to_bytes(8, "little"),
            )
        except UcError:
            pass

    # ── Main loop ───────────────────────────────────────────────────────

    def _final_memory_sweep(self):
        """After emulation, scan every mapped heap / image write page for
        UTF-16 strings starting with our device-name prefixes. Catches
        names that were built but never passed to an API we stubbed."""
        utf16_prefixes = [p.encode("utf-16-le") for p in INTERESTING_PREFIXES]

        for region_base, region_size in (
            (HEAP_BASE, self.heap_cursor - HEAP_BASE),
            (STACK_BASE, STACK_SIZE),
        ):
            if region_size <= 0:
                continue
            try:
                data = bytes(self.uc.mem_read(region_base, region_size))
            except UcError:
                continue
            for prefix in utf16_prefixes:
                idx = 0
                while True:
                    idx = data.find(prefix, idx)
                    if idx < 0:
                        break
                    # Extract until NUL-16
                    end = idx
                    while end < len(data) - 1:
                        if data[end] == 0 and data[end + 1] == 0:
                            break
                        end += 2
                    try:
                        s = data[idx:end].decode("utf-16-le", errors="ignore")
                    except Exception:
                        s = ""
                    if s and 4 < len(s) < 256:
                        self.found_names.add(s)
                    idx = end + 2

    def run(self, max_insns: int = 100_000):
        self._max_insns = max_insns
        try:
            self.uc.emu_start(self.entry_va, 0, count=max_insns)
        except UcError:
            pass
        except Exception:
            pass
        # Always try the memory sweep even if emulation aborted early
        try:
            self._final_memory_sweep()
        except Exception:
            pass
