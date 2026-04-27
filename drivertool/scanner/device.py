"""Device creation and access control scanning."""
from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING, Dict, List, Optional

import capstone.x86_const as x86c

from drivertool.constants import Severity
from drivertool.models import Finding
from drivertool.ioctl import decode_ioctl, is_valid_ioctl

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class DeviceScanMixin:
    """Mixin: scan_device_creation, scan_access_control, scan_device_access_security"""

    def scan_device_creation(self):
        if not self.pe.device_names:
            return
        for name in self.pe.device_names:
            user_accessible = (name.startswith("\\DosDevices\\") or
                               name.startswith("\\??\\") or
                               name.startswith("\\GLOBAL??\\"))
            is_guid = name.startswith("DeviceInterface:")
            if is_guid:
                self.findings.append(Finding(
                    title=f"Device interface GUID: {name}",
                    severity=Severity.MEDIUM,
                    description="Device interface GUID found — accessible via "
                                "SetupDiGetClassDevs / SetupDiGetDeviceInterfaceDetail "
                                "from user-mode. May expose IOCTL surface.",
                    location="String References",
                    details={"device_name": name, "user_accessible": "True"},
                ))
            else:
                self.findings.append(Finding(
                    title=f"Device name found: {name}",
                    severity=Severity.MEDIUM if user_accessible else Severity.LOW,
                    description="User-accessible device via symbolic link" if user_accessible
                                else "Kernel device object found",
                    location="String References",
                    details={"device_name": name, "user_accessible": str(user_accessible)},
                ))

    def scan_access_control(self):
        """
        Audit access control & input validation in IOCTL handlers.
        Checks for: PreviousMode, buffer length validation, NULL checks,
        privilege checks, secure device creation, ObReferenceObjectByHandle
        AccessMode, and default IOCTL case handling.
        """
        all_imports = [f for funcs in self.pe.imports.values() for f in funcs]
        all_imports_set = set(all_imports)

        # ── A. PreviousMode / RequestorMode check ──────────────────────────
        has_previous_mode = ("ExGetPreviousMode" in all_imports_set or
                             "KeGetPreviousMode" in all_imports_set)
        if not has_previous_mode:
            # Also scan for inline reads: mov eax, gs:[0x188] → mov al, [rax+0x232]
            # (KTHREAD.PreviousMode at offset 0x232 on Win10+)
            found_inline = False
            ep_addr, ep_bytes = self.pe.get_entry_point_bytes(count=2048)
            if ep_bytes:
                insns = self.dis.disassemble_function(ep_bytes, ep_addr, max_insns=500)
                for insn in insns:
                    if insn.mnemonic == "mov" and len(insn.operands) == 2:
                        src = insn.operands[1]
                        if src.type == x86c.X86_OP_MEM:
                            # PreviousMode offset: 0x232 (Win10+), 0x1f6 (older)
                            if src.mem.disp in (0x232, 0x1F6, 0x234):
                                found_inline = True
                                break
            if not found_inline:
                self.findings.append(Finding(
                    title="No PreviousMode / RequestorMode check detected",
                    severity=Severity.HIGH,
                    description="Driver does not import ExGetPreviousMode or KeGetPreviousMode "
                                "and no inline KTHREAD.PreviousMode read was found. "
                                "Without checking PreviousMode, a kernel-mode caller could be "
                                "impersonated, or user-mode requests may bypass validation. "
                                "IOCTLs should verify RequestorMode == UserMode before trusting input.",
                    location="Import Table / DriverEntry",
                ))

        # ── B. InputBufferLength validation ────────────────────────────────
        # In IOCTL handlers using METHOD_BUFFERED, the driver should check
        # IO_STACK_LOCATION->Parameters.DeviceIoControl.InputBufferLength
        # which is at [IoStackLocation + 0x10] (x64).
        # Scan each known IOCTL handler for CMP of memory operand vs immediate.
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        handlers_without_length_check = []
        for code in self.ioctl_codes:
            method = code & 0x3
            if method == 3:
                # METHOD_NEITHER — different buffer passing, skip this check
                continue
            # Find the handler VA from ioctl_purposes tracking or ioctl_map
            # We re-scan the IOCTL dispatch to get handler addresses
            # Use the findings to locate handler VAs
            handler_va = None
            for f in self.findings:
                if f.ioctl_code == code and f.details and "handler" in f.details:
                    handler_va = int(f.details["handler"], 16)
                    break
            if not handler_va:
                continue

            rva = handler_va - image_base
            hbytes = self.pe.get_bytes_at_rva(rva, 4096)
            if not hbytes:
                continue
            insns = self.dis.disassemble_function(hbytes, handler_va, max_insns=300)
            has_length_cmp = False
            for insn in insns:
                if insn.mnemonic == "cmp" and len(insn.operands) == 2:
                    src = insn.operands[0]
                    imm_op = insn.operands[1]
                    # Check for cmp [reg+disp], imm  or  cmp reg, imm (small size value)
                    if src.type == x86c.X86_OP_MEM and imm_op.type == x86c.X86_OP_IMM:
                        # IO_STACK_LOCATION offsets for buffer lengths: 0x08, 0x10
                        if src.mem.disp in (0x08, 0x10):
                            has_length_cmp = True
                            break
                    # cmp reg, small_imm (likely a sizeof check)
                    if (src.type == x86c.X86_OP_REG and
                            imm_op.type == x86c.X86_OP_IMM and
                            0 < (imm_op.imm & 0xFFFFFFFF) < 0x10000):
                        # Could be length validation — look for jb/jbe/jl/jle after
                        idx = insns.index(insn) if insn in insns else -1
                        if idx >= 0 and idx + 1 < len(insns):
                            nxt = insns[idx + 1]
                            if nxt.mnemonic in ("jb", "jbe", "jl", "jle", "ja", "jae",
                                                "jg", "jge", "jnb", "jnbe"):
                                has_length_cmp = True
                                break
            if not has_length_cmp:
                decoded = decode_ioctl(code)
                handlers_without_length_check.append(decoded["code"])

        if handlers_without_length_check:
            self.findings.append(Finding(
                title="IOCTL handlers missing InputBufferLength validation",
                severity=Severity.HIGH,
                description=f"The following IOCTL handlers do not appear to validate "
                            f"InputBufferLength before processing the buffer: "
                            f"{', '.join(handlers_without_length_check)}. "
                            f"Without size checks, a short buffer could cause pool "
                            f"overread or out-of-bounds writes.",
                location="IOCTL handlers",
                details={"ioctls": handlers_without_length_check},
            ))

        # ── C. NULL buffer check ───────────────────────────────────────────
        # After getting SystemBuffer, driver should check if it's NULL.
        # Pattern: test reg, reg / jz (right after reading from IRP)
        handlers_without_null_check = []
        for code in self.ioctl_codes:
            method = code & 0x3
            if method == 3:
                continue
            handler_va = None
            for f in self.findings:
                if f.ioctl_code == code and f.details and "handler" in f.details:
                    handler_va = int(f.details["handler"], 16)
                    break
            if not handler_va:
                continue

            rva = handler_va - image_base
            hbytes = self.pe.get_bytes_at_rva(rva, 4096)
            if not hbytes:
                continue
            insns = self.dis.disassemble_function(hbytes, handler_va, max_insns=300)
            has_null_check = False
            for i, insn in enumerate(insns):
                # test reg, reg followed by jz/je = NULL check
                if insn.mnemonic == "test" and len(insn.operands) == 2:
                    if (insn.operands[0].type == x86c.X86_OP_REG and
                            insn.operands[1].type == x86c.X86_OP_REG and
                            insn.operands[0].reg == insn.operands[1].reg):
                        if i + 1 < len(insns) and insns[i + 1].mnemonic in ("je", "jz"):
                            has_null_check = True
                            break
                # cmp reg, 0 followed by je/jz
                if (insn.mnemonic == "cmp" and len(insn.operands) == 2 and
                        insn.operands[1].type == x86c.X86_OP_IMM and
                        insn.operands[1].imm == 0):
                    if i + 1 < len(insns) and insns[i + 1].mnemonic in ("je", "jz"):
                        has_null_check = True
                        break
            if not has_null_check:
                decoded = decode_ioctl(code)
                handlers_without_null_check.append(decoded["code"])

        if handlers_without_null_check:
            self.findings.append(Finding(
                title="IOCTL handlers missing NULL buffer check",
                severity=Severity.MEDIUM,
                description=f"These IOCTL handlers may not check for NULL SystemBuffer "
                            f"before dereferencing: {', '.join(handlers_without_null_check)}. "
                            f"A zero-length IOCTL request can result in SystemBuffer=NULL, "
                            f"causing a kernel NULL-pointer dereference (BSOD).",
                location="IOCTL handlers",
                details={"ioctls": handlers_without_null_check},
            ))

        # ── C2. IoCreateUnprotectedSymbolicLink ─────────────────────────────
        # This API creates a symlink with a permissive default DACL —
        # any unprivileged user can open OR replace the symlink, which is
        # a long-standing privilege-escalation / link-following primitive.
        if "IoCreateUnprotectedSymbolicLink" in all_imports_set:
            self.findings.append(Finding(
                title="IoCreateUnprotectedSymbolicLink in use",
                severity=Severity.HIGH,
                description="Driver imports IoCreateUnprotectedSymbolicLink, which "
                            "creates a symbolic link with a permissive DACL "
                            "(any user may modify). This enables symlink "
                            "redirection attacks — an unprivileged process can "
                            "replace the link and have the driver (or other "
                            "callers) open an attacker-controlled target. Prefer "
                            "IoCreateSymbolicLink with IoCreateDeviceSecure + SDDL.",
                location="Import Table",
            ))

        # ── C3. REG_LINK registry symbolic link creation ────────────────────
        # ZwSetValueKey(..., Type=REG_LINK (6), Data=\KnownTarget) turns a
        # registry value into an object-manager symlink. Attackers abuse this
        # to redirect key lookups to attacker-controlled hives (CVE-2019-0808
        # family). Detection: find calls to ZwSetValueKey / NtSetValueKey
        # where the 4th arg (r9d on x64) is loaded with the constant 6.
        if ("ZwSetValueKey" in all_imports_set or
                "NtSetValueKey" in all_imports_set):
            reg_link_sites = self._scan_reg_link_set_value()
            if reg_link_sites:
                self.findings.append(Finding(
                    title="Registry symbolic-link creation (REG_LINK)",
                    severity=Severity.HIGH,
                    description="Driver calls ZwSetValueKey with Type=REG_LINK (6), "
                                "creating a registry-based symbolic link. REG_LINK "
                                "values redirect key lookups to an attacker-chosen "
                                "target — a well-known privilege-escalation primitive. "
                                "Ensure the hosting key DACL prevents untrusted callers "
                                "from replacing the link value, and consider whether "
                                "the redirection target is attacker-writable.",
                    location=f"{len(reg_link_sites)} call site(s)",
                    details={"call_sites": [hex(va) for va in reg_link_sites]},
                ))

        # ── D. Privilege check (SeSinglePrivilegeCheck, SeAccessCheck) ─────
        privilege_apis = {"SeSinglePrivilegeCheck", "SePrivilegeCheck",
                          "SeAccessCheck", "SeFastTraverseCheck"}
        has_priv_check = bool(all_imports_set & privilege_apis)
        if not has_priv_check and self.ioctl_codes:
            self.findings.append(Finding(
                title="No privilege check APIs imported",
                severity=Severity.MEDIUM,
                description="Driver handles IOCTLs but does not import "
                            "SeSinglePrivilegeCheck, SePrivilegeCheck, or SeAccessCheck. "
                            "Sensitive operations should verify caller privileges beyond "
                            "just device handle access rights.",
                location="Import Table",
                details={"checked_apis": sorted(privilege_apis)},
            ))

        # ── E. Secure device creation audit ────────────────────────────────
        has_create_device = "IoCreateDevice" in all_imports_set
        has_create_secure = "IoCreateDeviceSecure" in all_imports_set
        has_wdm_security = "WdmlibIoCreateDeviceSecure" in all_imports_set

        if has_create_device and not has_create_secure and not has_wdm_security:
            # Check if FILE_DEVICE_SECURE_OPEN (0x100) flag is used
            # Scan DriverEntry for mov with 0x100 flag near IoCreateDevice call
            found_secure_open = False
            ep_addr, ep_bytes = self.pe.get_entry_point_bytes(count=2048)
            if ep_bytes:
                insns = self.dis.disassemble_function(ep_bytes, ep_addr, max_insns=500)
                for insn in insns:
                    if insn.mnemonic == "mov" and len(insn.operands) == 2:
                        op = insn.operands[1]
                        if op.type == x86c.X86_OP_IMM:
                            val = op.imm & 0xFFFFFFFF
                            # FILE_DEVICE_SECURE_OPEN = 0x100
                            if val & 0x100:
                                found_secure_open = True
                                break

            if not found_secure_open:
                self.findings.append(Finding(
                    title="IoCreateDevice without FILE_DEVICE_SECURE_OPEN",
                    severity=Severity.HIGH,
                    description="Driver uses IoCreateDevice instead of IoCreateDeviceSecure "
                                "and FILE_DEVICE_SECURE_OPEN flag was not detected. "
                                "Without this flag, the device object inherits permissive "
                                "default security, allowing any user to open a handle. "
                                "Use IoCreateDeviceSecure with an SDDL string to restrict access.",
                    location="Import Table / DriverEntry",
                ))

            # Also check for SDDL string presence
            sddl_found = False
            for s in self.pe.device_names:
                if "D:" in s or "S:" in s:
                    sddl_found = True
                    break
            # Scan raw binary for SDDL pattern
            if not sddl_found:
                raw = self.pe.raw
                if b"D:P(" in raw or b"D\x00:\x00P\x00(\x00" in raw:
                    sddl_found = True

            if not sddl_found and has_create_device:
                self.findings.append(Finding(
                    title="No SDDL security descriptor found",
                    severity=Severity.MEDIUM,
                    description="No SDDL security descriptor string detected in the binary. "
                                "Drivers should apply SDDL-based ACLs to their device objects "
                                "to control which users/groups can open handles.",
                    location="Binary strings",
                ))

        # ── F. ObReferenceObjectByHandle AccessMode audit ──────────────────
        if "ObReferenceObjectByHandle" in all_imports_set:
            # Scan for calls to ObReferenceObjectByHandle where AccessMode
            # argument (3rd param, r8 on x64) is set to 0 (KernelMode).
            # Pattern: xor r8d, r8d  or  mov r8d, 0  before call ObRef...
            for code in self.ioctl_codes:
                handler_va = None
                for f in self.findings:
                    if f.ioctl_code == code and f.details and "handler" in f.details:
                        handler_va = int(f.details["handler"], 16)
                        break
                if not handler_va:
                    continue

                rva = handler_va - image_base
                hbytes = self.pe.get_bytes_at_rva(rva, 4096)
                if not hbytes:
                    continue
                insns = self.dis.disassemble_function(hbytes, handler_va, max_insns=400)
                call_targets = self.dis.find_all_call_targets(insns)

                for ci, (call_addr, target) in enumerate(call_targets):
                    fname = self.pe.iat_map.get(target, "")
                    if fname != "ObReferenceObjectByHandle":
                        continue

                    # Backward scan up to 10 insns before call for r8 setup
                    call_idx = None
                    for idx, insn in enumerate(insns):
                        if insn.address == call_addr:
                            call_idx = idx
                            break
                    if call_idx is None:
                        continue

                    kernel_mode_set = False
                    for bi in range(max(0, call_idx - 10), call_idx):
                        insn = insns[bi]
                        if len(insn.operands) < 2:
                            continue
                        dst = insn.operands[0]
                        if dst.type != x86c.X86_OP_REG:
                            continue
                        # r8d = X86_REG_R8D, r8 = X86_REG_R8
                        reg_name = insn.reg_name(dst.reg)
                        if reg_name not in ("r8", "r8d"):
                            continue
                        # xor r8d, r8d  → KernelMode(0)
                        if insn.mnemonic == "xor":
                            src = insn.operands[1]
                            if src.type == x86c.X86_OP_REG and src.reg == dst.reg:
                                kernel_mode_set = True
                                break
                        # mov r8d, 0
                        if insn.mnemonic == "mov":
                            src = insn.operands[1]
                            if src.type == x86c.X86_OP_IMM and src.imm == 0:
                                kernel_mode_set = True
                                break
                            # mov r8d, 1 → UserMode — this is fine
                            if src.type == x86c.X86_OP_IMM and src.imm == 1:
                                break

                    if kernel_mode_set:
                        decoded = decode_ioctl(code)
                        self.findings.append(Finding(
                            title=f"ObReferenceObjectByHandle with KernelMode in IOCTL {decoded['code']}",
                            severity=Severity.CRITICAL,
                            description="ObReferenceObjectByHandle is called with AccessMode=KernelMode(0) "
                                        "inside an IOCTL handler. This bypasses access checks on the "
                                        "handle, allowing a user-mode caller to pass a handle they "
                                        "don't actually have access to. The driver should use "
                                        "ExGetPreviousMode() or pass UserMode as the AccessMode.",
                            location=f"0x{call_addr:X}",
                            ioctl_code=code,
                            details={"function": "ObReferenceObjectByHandle",
                                     "access_mode": "KernelMode (0)"},
                        ))

        # ── G. Default IOCTL case detection ────────────────────────────────
        # A well-written IOCTL dispatcher returns STATUS_INVALID_DEVICE_REQUEST
        # (0xC0000010) for unknown IOCTL codes. Check if this constant appears.
        if self.ioctl_codes:
            # Find the IRP_MJ_DEVICE_CONTROL handler
            dev_ctrl_va = None
            for f in self.findings:
                if f.title and "IRP_MJ_DEVICE_CONTROL" in f.title and "handler" in f.title.lower():
                    if f.details and "handler" in f.details:
                        dev_ctrl_va = int(f.details["handler"], 16)
                        break
                    elif f.location and f.location.startswith("0x"):
                        dev_ctrl_va = int(f.location, 16)
                        break

            if dev_ctrl_va:
                rva = dev_ctrl_va - image_base
                dispatch_bytes = self.pe.get_bytes_at_rva(rva, 8192)
                if dispatch_bytes:
                    insns = self.dis.disassemble_function(
                        dispatch_bytes, dev_ctrl_va, max_insns=800)
                    has_invalid_device_req = False
                    # STATUS_INVALID_DEVICE_REQUEST = 0xC0000010
                    for insn in insns:
                        if insn.mnemonic == "mov" and len(insn.operands) == 2:
                            op = insn.operands[1]
                            if op.type == x86c.X86_OP_IMM:
                                val = op.imm & 0xFFFFFFFF
                                if val == 0xC0000010:
                                    has_invalid_device_req = True
                                    break

                    if not has_invalid_device_req:
                        self.findings.append(Finding(
                            title="IOCTL dispatch missing default case (STATUS_INVALID_DEVICE_REQUEST)",
                            severity=Severity.MEDIUM,
                            description="The IOCTL dispatch handler does not appear to return "
                                        "STATUS_INVALID_DEVICE_REQUEST (0xC0000010) for unrecognized "
                                        "IOCTL codes. A missing default case could lead to "
                                        "uninitialized status codes, information leaks from the "
                                        "output buffer, or unexpected behavior on unknown IOCTLs.",
                            location=f"0x{dev_ctrl_va:X}",
                        ))

    def scan_device_access_security(self):
        """
        Deep audit of how the device object is created and whether usermode
        processes can open it.  Checks:
          1. IoCreateDevice vs IoCreateDeviceSecure
          2. FILE_DEVICE_SECURE_OPEN flag
          3. SDDL descriptor (parsed if present)
          4. DO_EXCLUSIVE flag (single handle)
          5. Symbolic link exposure (\\DosDevices / \\??)
          6. IRP_MJ_CREATE handler — does it validate callers?
          7. Device type (NULL / custom)
          8. Direct device name (no symlink) reachable from usermode
        """
        all_imports = set(f for funcs in self.pe.imports.values() for f in funcs)
        image_base = self.pe.pe.OPTIONAL_HEADER.ImageBase
        ep_addr, ep_bytes = self.pe.get_entry_point_bytes(count=4096)
        if not ep_bytes:
            return
        insns = self.dis.disassemble_function(ep_bytes, ep_addr, max_insns=800)

        # ── 1. Detect IoCreateDevice call arguments ──────────────────────
        has_create_device = "IoCreateDevice" in all_imports
        has_create_secure = ("IoCreateDeviceSecure" in all_imports or
                             "WdmlibIoCreateDeviceSecure" in all_imports or
                             "IoCreateDeviceObjectEx" in all_imports)
        has_device_interface = "IoRegisterDeviceInterface" in all_imports

        # ── 2. Scan for device characteristics flags near IoCreateDevice ──
        # IoCreateDevice(DriverObj, ExtSize, DevName, DeviceType, Characteristics, Exclusive, &DevObj)
        # On x64 ABI: r9d = DeviceType, [rsp+0x20] = Characteristics, [rsp+0x28] = Exclusive
        found_secure_open = False
        found_exclusive = False
        found_device_type = None
        create_device_addr = None

        for i, insn in enumerate(insns):
            if insn.mnemonic == "call" and insn.operands:
                op = insn.operands[0]
                target = None
                if op.type == x86c.X86_OP_IMM:
                    target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and op.mem.index == 0):
                    target = insn.address + insn.size + op.mem.disp
                if target and self.pe.iat_map.get(target, "") in (
                        "IoCreateDevice", "IoCreateDeviceSecure",
                        "WdmlibIoCreateDeviceSecure"):
                    create_device_addr = insn.address
                    # Scan backwards to find argument setup
                    for j in range(max(0, i - 20), i):
                        prev = insns[j]
                        if prev.mnemonic == "mov" and len(prev.operands) == 2:
                            dst, src = prev.operands[0], prev.operands[1]
                            # Characteristics on stack [rsp+0x20]
                            if (dst.type == x86c.X86_OP_MEM and
                                    dst.mem.base == x86c.X86_REG_RSP and
                                    dst.mem.disp == 0x20 and
                                    src.type == x86c.X86_OP_IMM):
                                val = src.imm & 0xFFFFFFFF
                                if val & 0x100:
                                    found_secure_open = True
                            # Exclusive on stack [rsp+0x28]
                            if (dst.type == x86c.X86_OP_MEM and
                                    dst.mem.base == x86c.X86_REG_RSP and
                                    dst.mem.disp == 0x28 and
                                    src.type == x86c.X86_OP_IMM):
                                if src.imm == 1:
                                    found_exclusive = True
                            # DeviceType in r9d (4th param)
                            if (dst.type == x86c.X86_OP_REG and
                                    dst.reg in (x86c.X86_REG_R9, x86c.X86_REG_R9D) and
                                    src.type == x86c.X86_OP_IMM):
                                found_device_type = src.imm & 0xFFFF
                    break

        # ── 3. Build device access report ────────────────────────────────
        device_access = {
            "create_api": "IoCreateDeviceSecure" if has_create_secure
                          else "IoCreateDevice" if has_create_device
                          else "Unknown",
            "secure_open": found_secure_open,
            "exclusive": found_exclusive,
            "device_type": found_device_type,
            "device_interface": has_device_interface,
            "symlinks": [],
            "sddl": None,
            "create_handler_validates": False,
            "issues": [],
        }
        self.device_access = device_access

        # Check symbolic links
        for dn in self.pe.device_names:
            if (dn.startswith("\\DosDevices\\") or dn.startswith("\\??\\") or
                    dn.startswith("\\GLOBAL??\\") or dn.startswith("DeviceInterface:")):
                device_access["symlinks"].append(dn)

        # ── 4. SDDL extraction ───────────────────────────────────────────
        raw = self.pe.raw
        sddl_str = None
        # Try ASCII SDDL
        import re as _re
        for m in _re.finditer(rb'D:[A-Z(;]*(?:\([^)]+\))+', raw):
            sddl_str = m.group(0).decode("ascii", errors="replace")
            break
        # Try wide-char SDDL
        if not sddl_str:
            for m in _re.finditer(rb'D\x00:\x00[A-Z\x00(;\x00]*(?:\(\x00[^)]+\)\x00)+', raw):
                try:
                    sddl_str = m.group(0).decode("utf-16-le", errors="replace")
                except Exception:
                    pass
                break
        device_access["sddl"] = sddl_str

        # Parse SDDL to check if it restricts access
        sddl_allows_everyone = False
        sddl_allows_users = False
        if sddl_str:
            # WD = Everyone, BU = Built-in Users, IU = Interactive Users
            if "WD" in sddl_str:
                sddl_allows_everyone = True
            if "BU" in sddl_str or "IU" in sddl_str:
                sddl_allows_users = True

        # ── 5. Analyze IRP_MJ_CREATE handler for caller validation ────────
        create_handler_va = None
        for f in self.findings:
            if f.title and "IRP_MJ_CREATE" in f.title and "handler" in f.title.lower():
                if f.details and "handler" in f.details:
                    create_handler_va = int(f.details["handler"], 16)
                elif f.location and f.location.startswith("0x"):
                    create_handler_va = int(f.location, 16)
                break

        create_checks = []
        if create_handler_va:
            rva = create_handler_va - image_base
            data = self.pe.get_bytes_at_rva(rva, 4096)
            if data:
                handler_insns = self.dis.disassemble_function(
                    data, create_handler_va, max_insns=300)
                # Look for API calls in IRP_MJ_CREATE handler
                for hi in handler_insns:
                    if hi.mnemonic == "call" and hi.operands:
                        op = hi.operands[0]
                        target = None
                        if op.type == x86c.X86_OP_IMM:
                            target = op.imm
                        elif (op.type == x86c.X86_OP_MEM and
                              op.mem.base == x86c.X86_REG_RIP and
                              op.mem.index == 0):
                            target = hi.address + hi.size + op.mem.disp
                        if target:
                            fn = self.pe.iat_map.get(target, "")
                            if fn in ("SeSinglePrivilegeCheck", "SeAccessCheck",
                                      "SePrivilegeCheck", "SeFastTraverseCheck",
                                      "IoCheckShareAccess", "IoCheckDesiredAccess"):
                                create_checks.append(fn)
                            elif fn in ("ExGetPreviousMode", "KeGetPreviousMode"):
                                create_checks.append("PreviousModeCheck")
                            elif fn in ("PsGetCurrentProcessId", "PsGetCurrentProcess"):
                                create_checks.append("ProcessIdentityCheck")
                            elif fn == "IoIsOperationSynchronous":
                                create_checks.append("SyncCheck")

                # Check for STATUS_ACCESS_DENIED in create handler
                for hi in handler_insns:
                    if hi.mnemonic == "mov" and len(hi.operands) == 2:
                        src = hi.operands[1]
                        if src.type == x86c.X86_OP_IMM:
                            val = src.imm & 0xFFFFFFFF
                            if val == 0xC0000022:  # STATUS_ACCESS_DENIED
                                create_checks.append("AccessDeniedPath")
                            elif val == 0xC000000D:  # STATUS_INVALID_PARAMETER
                                create_checks.append("ParameterValidation")

                # Check for a trivial create handler (just returns STATUS_SUCCESS)
                if len(handler_insns) <= 10:
                    trivial = True
                    for hi in handler_insns:
                        if hi.mnemonic == "call":
                            trivial = False
                            break
                    if trivial:
                        create_checks.append("TRIVIAL_HANDLER")

        if create_checks:
            device_access["create_handler_validates"] = (
                "TRIVIAL_HANDLER" not in create_checks and len(create_checks) > 0)

        # ── 6. Generate findings ─────────────────────────────────────────

        # Issue: No IoCreateDeviceSecure
        if has_create_device and not has_create_secure:
            device_access["issues"].append("uses_IoCreateDevice")

        # Issue: No FILE_DEVICE_SECURE_OPEN
        if has_create_device and not found_secure_open:
            device_access["issues"].append("no_FILE_DEVICE_SECURE_OPEN")

        # Issue: Not exclusive
        if has_create_device and not found_exclusive:
            device_access["issues"].append("not_exclusive")

        # Issue: Has symlinks (user-reachable)
        if device_access["symlinks"]:
            device_access["issues"].append("has_symlinks")

        # Issue: SDDL allows everyone
        if sddl_allows_everyone:
            device_access["issues"].append("sddl_allows_everyone")
        elif sddl_allows_users:
            device_access["issues"].append("sddl_allows_users")
        elif has_create_device and not sddl_str and not has_create_secure:
            device_access["issues"].append("no_sddl")

        # Issue: Trivial IRP_MJ_CREATE (no validation)
        if "TRIVIAL_HANDLER" in create_checks:
            device_access["issues"].append("trivial_create_handler")
        elif create_handler_va and not create_checks:
            device_access["issues"].append("create_no_access_checks")

        # Issue: NULL device type
        if found_device_type == 0x22:
            pass  # FILE_DEVICE_UNKNOWN is common but not great
        elif found_device_type is not None and found_device_type < 0x8000:
            # Microsoft-reserved device types
            device_access["issues"].append("ms_reserved_device_type")

        # Device interface (less restrictive by default)
        if has_device_interface and not has_create_secure:
            device_access["issues"].append("device_interface_no_security")

        # ── Summary finding ──────────────────────────────────────────────
        issues = device_access["issues"]
        if not issues:
            sev = Severity.LOW
            desc = ("Device access security looks reasonable. "
                    f"API: {device_access['create_api']}, "
                    f"Secure Open: {found_secure_open}, "
                    f"Exclusive: {found_exclusive}")
        else:
            critical_issues = {"sddl_allows_everyone", "trivial_create_handler",
                               "no_sddl", "uses_IoCreateDevice"}
            if issues_set := set(issues) & critical_issues:
                sev = Severity.HIGH
            else:
                sev = Severity.MEDIUM
            desc_parts = []
            if "uses_IoCreateDevice" in issues:
                desc_parts.append("Uses IoCreateDevice (not IoCreateDeviceSecure)")
            if "no_FILE_DEVICE_SECURE_OPEN" in issues:
                desc_parts.append("Missing FILE_DEVICE_SECURE_OPEN flag")
            if "not_exclusive" in issues:
                desc_parts.append("Device is not exclusive (multiple handles allowed)")
            if "has_symlinks" in issues:
                desc_parts.append(f"Exposed via symlinks: {', '.join(device_access['symlinks'])}")
            if "sddl_allows_everyone" in issues:
                desc_parts.append("SDDL grants access to Everyone (WD)")
            if "sddl_allows_users" in issues:
                desc_parts.append("SDDL grants access to regular users (BU/IU)")
            if "no_sddl" in issues:
                desc_parts.append("No SDDL security descriptor — default permissive ACL")
            if "trivial_create_handler" in issues:
                desc_parts.append("IRP_MJ_CREATE is trivial (no access checks, just STATUS_SUCCESS)")
            if "create_no_access_checks" in issues:
                desc_parts.append("IRP_MJ_CREATE handler has no privilege/access validation calls")
            if "device_interface_no_security" in issues:
                desc_parts.append("Uses IoRegisterDeviceInterface without security restrictions")
            if "ms_reserved_device_type" in issues:
                desc_parts.append(f"Uses Microsoft-reserved device type 0x{found_device_type:X}")
            desc = "; ".join(desc_parts)

        self.findings.append(Finding(
            title="Device Access Security Audit",
            severity=sev,
            description=desc,
            location=f"0x{create_device_addr:X}" if create_device_addr else "DriverEntry",
            details={
                "create_api": device_access["create_api"],
                "secure_open": str(found_secure_open),
                "exclusive": str(found_exclusive),
                "device_type": f"0x{found_device_type:X}" if found_device_type is not None else "unknown",
                "sddl": sddl_str or "none",
                "symlinks": device_access["symlinks"],
                "create_checks": create_checks,
                "issues": issues,
            },
        ))

    def _scan_reg_link_set_value(self) -> List[int]:
        """Find ZwSetValueKey / NtSetValueKey calls whose Type arg is REG_LINK.

        ZwSetValueKey(HANDLE, PUNICODE_STRING, ULONG TitleIndex,
                      ULONG Type, PVOID Data, ULONG DataSize)
        On x64 the 4th arg (Type) is in r9d. A `mov r9d, 6` shortly before
        the call marks REG_LINK creation — the registry-symlink primitive.
        """
        targets = {"ZwSetValueKey", "NtSetValueKey"}
        target_iat = {addr for addr, name in self.pe.iat_map.items()
                      if name in targets}
        if not target_iat:
            return []

        R9_REGS = {x86c.X86_REG_R9, x86c.X86_REG_R9D,
                   x86c.X86_REG_R9W, x86c.X86_REG_R9B}
        hits: List[int] = []
        seen: set = set()

        for sec_va, sec_data in self.pe.get_code_sections():
            insns = self.dis.disassemble_function(
                sec_data, sec_va, max_insns=200000)
            for i, insn in enumerate(insns):
                if insn.mnemonic != "call" or not insn.operands:
                    continue
                op = insn.operands[0]
                target = None
                if op.type == x86c.X86_OP_IMM:
                    target = op.imm
                elif (op.type == x86c.X86_OP_MEM and
                      op.mem.base == x86c.X86_REG_RIP and
                      op.mem.index == 0):
                    target = insn.address + insn.size + op.mem.disp
                if target not in target_iat:
                    continue
                # Walk back for `mov r9*, 6`; any intervening call clobbers r9
                for j in range(i - 1, max(-1, i - 30), -1):
                    prev = insns[j]
                    if prev.mnemonic == "call":
                        break
                    if (prev.mnemonic == "mov" and len(prev.operands) == 2):
                        dst, src = prev.operands[0], prev.operands[1]
                        if (dst.type == x86c.X86_OP_REG and
                                dst.reg in R9_REGS and
                                src.type == x86c.X86_OP_IMM and
                                (src.imm & 0xFFFFFFFF) == 6):
                            if insn.address not in seen:
                                seen.add(insn.address)
                                hits.append(insn.address)
                            break
        return hits
