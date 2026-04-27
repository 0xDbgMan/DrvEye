"""PoC compilation utilities."""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional


def compile_poc(c_path: str) -> Optional[str]:
    """Compile a .c file to .exe using gcc (MinGW). Returns exe path or None on failure."""
    c_path = os.path.abspath(c_path)
    exe_path = c_path.rsplit(".", 1)[0] + ".exe"
    try:
        result = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-o", exe_path, c_path,
             "-lkernel32", "-static-libgcc"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            return exe_path
        # Fallback: plain gcc
        result2 = subprocess.run(
            ["gcc", "-o", exe_path, c_path, "-lkernel32"],
            capture_output=True, text=True, timeout=60,
        )
        if result2.returncode == 0:
            return exe_path
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def check_gcc() -> bool:
    """Check if gcc (MinGW) is available."""
    return shutil.which("gcc") is not None
