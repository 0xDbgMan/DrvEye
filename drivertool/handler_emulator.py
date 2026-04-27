"""HandlerEmulator — executes individual IOCTL handlers in a Unicorn sandbox.

For each discovered IOCTL code, synthesizes a fake IRP + IO_STACK_LOCATION,
sets the IoControlCode field, and emulates the handler.  Dangerous API calls
are intercepted and recorded, giving dynamic confirmation of which code paths
are reachable and which user-controlled arguments flow into sinks.

This turns static inference ("handler X might call MmMapIoSpace") into
dynamic validation ("handler X reaches MmMapIoSpace with RCX = 0xdeadbeef").
"""
from __future__ import annotations

import logging
import struct
from typing import Dict, List, Optional, Set, Tuple

from drivertool.emulator import (
    HEAP_BASE, HEAP_SIZE,
    STACK_BASE, STACK_SIZE,
    IAT_STUB_BASE, IAT_STUB_STRIDE,
)

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
# Synthetic kernel structure layouts (x64)
# ──────────────────────────────────────────────────────────────────────────

# IRP (simplified — only fields that matter for handler emulation)
IRP_SIZE = 0x100
IRP_OFF_SYSTEM_BUFFER = 0x18       # AssociatedIrp.SystemBuffer
IRP_OFF_CURRENT_STACK_LOCATION = 0xB8  # Tail.Overlay.CurrentStackLocation (x64)

# IO_STACK_LOCATION (simplified)
IOS_SIZE = 0x48
IOS_OFF_MAJOR_FUNCTION = 0x00
IOS_OFF_PARAMETERS = 0x08
IOS_OFF_IOCTL_CODE = 0x10          # Parameters.DeviceIoControl.IoControlCode
IOS_OFF_INPUT_BUFFER_LENGTH = 0x0C # Parameters.DeviceIoControl.InputBufferLength
IOS_OFF_OUTPUT_BUFFER_LENGTH = 0x08 # Parameters.DeviceIoControl.OutputBufferLength
IOS_OFF_TYPE3_INPUT_BUFFER = 0x18  # Parameters.DeviceIoControl.Type3InputBuffer

# Synthetic buffer size for user input
USER_BUFFER_SIZE = 0x1000


# ──────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────

def emulate_handler(pe_analyzer, handler_va: int, ioctl_code: int,
                    device_object_va: Optional[int] = None,
                    max_insns: int = 50_000) -> "HandlerResult":
    """Emulate a single IOCTL handler and return the APIs it reached.

    Args:
        pe_analyzer: PEAnalyzer instance
        handler_va: virtual address of the handler function
        ioctl_code: IOCTL code to place in IRP stack location
        device_object_va: optional fake PDEVICE_OBJECT pointer
        max_insns: instruction execution limit

    Returns:
        HandlerResult with api_hits and emulation metadata.
    """
    if not UNICORN_AVAILABLE:
        return HandlerResult(unavailable=True)
    try:
        emu = _HandlerEmulator(pe_analyzer, handler_va, ioctl_code,
                               device_object_va)
        return emu.run(max_insns=max_insns)
    except Exception:
        logger.debug("Handler emulation failed for 0x%X", handler_va,
                     exc_info=True)
        return HandlerResult(unavailable=True)


# ──────────────────────────────────────────────────────────────────────────
# Result dataclass
# ──────────────────────────────────────────────────────────────────────────

class HandlerResult:
    """Outcome of a single handler emulation run."""

    def __init__(self, unavailable: bool = False):
        self.unavailable = unavailable
        self.api_hits: List[Dict] = []          # {name, args, ret}
        self.insns_executed: int = 0
        self.memory_faults: int = 0
        self.aborted: bool = False
        self.abort_reason: str = ""

    def reached_dangerous_api(self, api_names: Set[str]) -> bool:
        return any(h["name"] in api_names for h in self.api_hits)

    def __repr__(self) -> str:
        return (f"HandlerResult(hits={len(self.api_hits)}, "
                f"insns={self.insns_executed}, aborted={self.aborted})")


# ──────────────────────────────────────────────────────────────────────────
# Emulator implementation
# ──────────────────────────────────────────────────────────────────────────

class _HandlerEmulator:
    """One-shot handler emulator.  Not reusable."""

    def __init__(self, pe_analyzer, handler_va: int, ioctl_code: int,
                 device_object_va: Optional[int] = None):
        self.pe = pe_analyzer
        self.handler_va = handler_va
        self.ioctl_code = ioctl_code
        self.result = HandlerResult()

        self._is_64bit = pe_analyzer.is_64bit
        mode = UC_MODE_64 if self._is_64bit else UC_MODE_32
        self.uc = Uc(UC_ARCH_X86, mode)

        self.image_base = pe_analyzer.pe.OPTIONAL_HEADER.ImageBase
        self.image_size = (pe_analyzer.pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF

        # Map PE image
        self.uc.mem_map(self.image_base, self.image_size)
        headers_size = pe_analyzer.pe.OPTIONAL_HEADER.SizeOfHeaders
        self.uc.mem_write(self.image_base, pe_analyzer.raw[:headers_size])
        for section in pe_analyzer.pe.sections:
            va = self.image_base + section.VirtualAddress
            raw = section.get_data()
            if raw and self.image_base <= va < self.image_base + self.image_size:
                try:
                    self.uc.mem_write(va, raw[:section.Misc_VirtualSize or len(raw)])
                except UcError:
                    pass

        # Stack
        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        rsp = STACK_BASE + STACK_SIZE - 0x1000
        sp_reg = UC_X86_REG_RSP if self._is_64bit else UC_X86_REG_ESP
        self.uc.reg_write(sp_reg, rsp)

        # Heap
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE)
        self.heap_cursor = HEAP_BASE

        # Build IAT stubs
        self.iat_to_stub: dict = {}
        self.stub_to_api: dict = {}
        self._setup_iat_stubs()

        # Synthetic kernel objects
        self._build_kernel_objects(device_object_va)

        # Sentinel return address
        self.sentinel_ret = IAT_STUB_BASE - 0x1000
        self.uc.mem_map(self.sentinel_ret & ~0xFFF, 0x1000)
        if self._is_64bit:
            sp = self.uc.reg_read(UC_X86_REG_RSP) - 8
            self.uc.mem_write(sp, self.sentinel_ret.to_bytes(8, "little"))
            self.uc.reg_write(UC_X86_REG_RSP, sp)
        else:
            self._push32(self.sentinel_ret)

        # Hooks
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self.uc.hook_add(
            UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_INVALID,
            self._mem_fault_hook,
        )

    # ── Heap helpers ────────────────────────────────────────────────────

    def _alloc(self, size: int) -> int:
        addr = self.heap_cursor
        size = (size + 0x1F) & ~0x1F
        if addr + size > HEAP_BASE + HEAP_SIZE:
            addr = HEAP_BASE
        self.heap_cursor = addr + size
        self.uc.mem_write(addr, b"\x00" * size)
        return addr

    def _push32(self, value: int):
        sp = self.uc.reg_read(UC_X86_REG_ESP) - 4
        self.uc.mem_write(sp, (value & 0xFFFFFFFF).to_bytes(4, "little"))
        self.uc.reg_write(UC_X86_REG_ESP, sp)

    # ── IAT stubbing ────────────────────────────────────────────────────

    def _setup_iat_stubs(self):
        self.uc.mem_map(IAT_STUB_BASE, 0x10000)
        self.uc.mem_write(IAT_STUB_BASE, b"\xC3" * 0x10000)
        cursor = IAT_STUB_BASE
        for iat_va, name in self.pe.iat_map.items():
            self.iat_to_stub[iat_va] = cursor
            self.stub_to_api[cursor] = name
            try:
                width = 8 if self._is_64bit else 4
                self.uc.mem_write(iat_va, cursor.to_bytes(width, "little"))
            except UcError:
                pass
            cursor += IAT_STUB_STRIDE
            if cursor >= IAT_STUB_BASE + 0x10000:
                break

    # ── Kernel object construction ──────────────────────────────────────

    def _build_kernel_objects(self, device_object_va: Optional[int]):
        # Fake PDEVICE_OBJECT
        if device_object_va is None:
            self.device_object = self._alloc(0x400)
        else:
            self.device_object = device_object_va

        # Fake user buffer (SystemBuffer)
        self.user_buffer = self._alloc(USER_BUFFER_SIZE)
        # Fill with a recognizable pattern so taint is obvious
        self.uc.mem_write(self.user_buffer, b"\x41" * USER_BUFFER_SIZE)

        # Fake IRP
        self.irp = self._alloc(IRP_SIZE)
        irp_data = bytearray(IRP_SIZE)
        # AssociatedIrp.SystemBuffer
        struct.pack_into("<Q", irp_data, IRP_OFF_SYSTEM_BUFFER, self.user_buffer)
        # Tail.Overlay.CurrentStackLocation → will point to IO_STACK_LOCATION
        self.ios = self._alloc(IOS_SIZE)
        struct.pack_into("<Q", irp_data, IRP_OFF_CURRENT_STACK_LOCATION, self.ios)
        self.uc.mem_write(self.irp, bytes(irp_data))

        # Fake IO_STACK_LOCATION
        ios_data = bytearray(IOS_SIZE)
        ios_data[IOS_OFF_MAJOR_FUNCTION] = 0x0E  # IRP_MJ_DEVICE_CONTROL
        struct.pack_into("<I", ios_data, IOS_OFF_IOCTL_CODE, self.ioctl_code)
        struct.pack_into("<I", ios_data, IOS_OFF_INPUT_BUFFER_LENGTH, USER_BUFFER_SIZE)
        struct.pack_into("<I", ios_data, IOS_OFF_OUTPUT_BUFFER_LENGTH, USER_BUFFER_SIZE)
        struct.pack_into("<Q", ios_data, IOS_OFF_TYPE3_INPUT_BUFFER, self.user_buffer)
        self.uc.mem_write(self.ios, bytes(ios_data))

    # ── Hook handlers ───────────────────────────────────────────────────

    def _mem_fault_hook(self, uc, access, address, size, value, _):
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000)
            uc.mem_write(page, b"\x00" * 0x1000)
        except UcError:
            pass
        self.result.memory_faults += 1
        return True

    def _code_hook(self, uc, address, size, _):
        self.result.insns_executed += 1
        if self.result.insns_executed >= 50_000:
            uc.emu_stop()
            self.result.aborted = True
            self.result.abort_reason = "instruction limit"
            return

        if address == self.sentinel_ret:
            uc.emu_stop()
            return

        if address in self.stub_to_api:
            api = self.stub_to_api[address]
            hit = self._handle_api(api)
            self.result.api_hits.append(hit)
            # Fake RET
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

    def _handle_api(self, api: str) -> Dict:
        if self._is_64bit:
            args = {
                "rcx": self.uc.reg_read(UC_X86_REG_RCX),
                "rdx": self.uc.reg_read(UC_X86_REG_RDX),
                "r8":  self.uc.reg_read(UC_X86_REG_R8),
                "r9":  self.uc.reg_read(UC_X86_REG_R9),
            }
        else:
            esp = self.uc.reg_read(UC_X86_REG_ESP)
            args = {
                "arg0": self._read_stack32(esp + 4),
                "arg1": self._read_stack32(esp + 8),
                "arg2": self._read_stack32(esp + 12),
                "arg3": self._read_stack32(esp + 16),
            }

        ret = 0
        # Dangerous API simulation — return benign success
        if api in ("MmMapIoSpace", "MmMapIoSpaceEx"):
            ret = self._alloc(0x1000)
        elif api in ("ExAllocatePool", "ExAllocatePoolWithTag",
                     "ExAllocatePool2", "ExAllocatePool3",
                     "ExAllocatePoolZero"):
            pool_size = args.get("rdx") or args.get("arg1") or 0x100
            ret = self._alloc(min(int(pool_size), 0x10000))
        elif api == "IoCompleteRequest":
            ret = 0
        elif api == "MmGetSystemRoutineAddress":
            ret = self._alloc(0x20)

        ret_reg = UC_X86_REG_RAX if self._is_64bit else UC_X86_REG_EAX
        self.uc.reg_write(ret_reg, ret)

        return {"name": api, "args": args, "ret": ret}

    def _read_stack32(self, addr: int) -> int:
        try:
            data = bytes(self.uc.mem_read(addr, 4))
            return int.from_bytes(data, "little")
        except UcError:
            return 0

    # ── Main loop ───────────────────────────────────────────────────────

    def run(self, max_insns: int = 50_000) -> HandlerResult:
        # Set up handler arguments
        if self._is_64bit:
            self.uc.reg_write(UC_X86_REG_RCX, self.device_object)
            self.uc.reg_write(UC_X86_REG_RDX, self.irp)
        else:
            # stdcall: push args right-to-left
            self._push32(self.irp)
            self._push32(self.device_object)

        try:
            self.uc.emu_start(self.handler_va, 0, count=max_insns)
        except UcError as e:
            self.result.aborted = True
            self.result.abort_reason = str(e)
        except Exception as e:
            self.result.aborted = True
            self.result.abort_reason = str(e)

        return self.result
