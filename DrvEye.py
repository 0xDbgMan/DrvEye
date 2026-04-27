#!/usr/bin/env python3
"""
TheDebugger.py — Windows Driver Static Analysis & Bug Hunter
Usage: python TheDebugger.py driver.sys [--save-pocs] [--source file.c ...]

Analyzes .sys kernel drivers for vulnerabilities and generates PoC exploits.

This is a thin entry point. All logic lives in the drivertool/ package.
"""
from drivertool.cli import main

if __name__ == "__main__":
    main()
