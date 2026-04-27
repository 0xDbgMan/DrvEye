"""IOCTL fuzzer harness generation."""
from __future__ import annotations

import os
from typing import Dict, List

from drivertool.ioctl import decode_ioctl


def generate_fuzzer_harness(device_name: str, ioctl_codes: List[int],
                           ioctl_purposes: Dict[int, str],
                           output_dir: str) -> List[str]:
    """
    Generate a Python ctypes fuzzer and a C skeleton harness for each
    discovered IOCTL — for use in authorised driver security testing.
    Returns list of written file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    written: List[str] = []
    dev_esc = device_name.replace("\\", "\\\\")

    # ── Python ctypes fuzzer ─────────────────────────────────────────────
    py = [
        "#!/usr/bin/env python3",
        '"""',
        f"IOCTL fuzzer — device: {device_name}",
        "For authorised security testing only.",
        '"""',
        "import ctypes, ctypes.wintypes, random, sys",
        "",
        f'DEVICE = r"{dev_esc}"',
        "k32 = ctypes.windll.kernel32",
        "",
        "def open_dev():",
        "    h = k32.CreateFileW(DEVICE, 0xC0000000, 0, None, 3, 0x80, None)",
        "    if h == ctypes.wintypes.HANDLE(-1).value:",
        "        raise OSError(f'Cannot open {DEVICE}: {k32.GetLastError()}')",
        "    return h",
        "",
        "def ioctl(h, code, size=0x200):",
        "    buf = (ctypes.c_byte * size)(*[random.randint(0,255) for _ in range(size)])",
        "    ret = ctypes.c_ulong(0)",
        "    k32.DeviceIoControl(h, code, buf, size, None, 0, ctypes.byref(ret), None)",
        "",
        "CODES = [",
    ]
    for c in ioctl_codes:
        p = ioctl_purposes.get(c, "")
        py.append(f"    0x{c:08X},  # {p}" if p else f"    0x{c:08X},")
    py += [
        "]",
        "",
        "h = open_dev()",
        "print(f'[+] Opened {DEVICE}')",
        "for code in CODES:",
        "    for _ in range(200):",
        "        ioctl(h, code)",
        "    print(f'  0x{code:08X} done')",
        "k32.CloseHandle(h)",
    ]
    py_path = os.path.join(output_dir, "ioctl_fuzzer.py")
    with open(py_path, "w") as f:
        f.write("\n".join(py) + "\n")
    written.append(py_path)

    # ── C skeleton ───────────────────────────────────────────────────────
    dev_c = device_name.replace("\\", "\\\\\\\\")
    c = [
        "/* Auto-generated IOCTL harness — authorised testing only",
        f" * Device: {device_name}",
        " * Compile: x86_64-w64-mingw32-gcc ioctl_harness.c -o ioctl_harness.exe */",
        "#include <windows.h>",
        "#include <stdio.h>",
        "#include <string.h>",
        f'#define DEVICE L"{dev_c}"',
        "",
    ]
    for code in ioctl_codes:
        p = ioctl_purposes.get(code, "")
        c.append(f"#define IOCTL_{code:08X} 0x{code:08X}  /* {p} */")
    c += [
        "",
        "int main(void){",
        "    HANDLE h=CreateFileW(DEVICE,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);",
        "    if(h==INVALID_HANDLE_VALUE){fprintf(stderr,\"[-] open failed\\n\");return 1;}",
        "    BYTE buf[0x200]; memset(buf,0x41,sizeof(buf)); DWORD r=0;",
    ]
    for code in ioctl_codes:
        c.append(f"    DeviceIoControl(h,0x{code:08X},buf,sizeof(buf),NULL,0,&r,NULL);")
        c.append(f'    printf("0x{code:08X} ret=%lu\\n",r);')
    c += ["    CloseHandle(h); return 0; }"]
    c_path = os.path.join(output_dir, "ioctl_harness.c")
    with open(c_path, "w") as f:
        f.write("\n".join(c) + "\n")
    written.append(c_path)
    return written
