"""
VulnScanner — composite vulnerability scanner built from mixin classes.

Each mixin provides a group of related scan methods. The VulnScanner class
inherits from all mixins and provides __init__ (shared state) and run_all
(orchestration).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict, List

from drivertool.constants import Severity
from drivertool.models import Finding

from drivertool.scanner.imports import ImportScanMixin
from drivertool.scanner.device import DeviceScanMixin
from drivertool.scanner.ioctl_scan import IOCTLScanMixin
from drivertool.scanner.memory import MemoryScanMixin
from drivertool.scanner.process import ProcessScanMixin
from drivertool.scanner.edr import EDRScanMixin
from drivertool.scanner.binary import BinaryScanMixin
from drivertool.scanner.taint_analysis import TaintScanMixin
from drivertool.scanner.z3_solver import Z3ScanMixin
from drivertool.scanner.exploit import ExploitScanMixin
from drivertool.scanner.certificate import CertScanMixin
from drivertool.scanner.yara_scan import YaraScanMixin, YARA_AVAILABLE
from drivertool.scanner.scoring import ScoringScanMixin

if TYPE_CHECKING:
    from drivertool.pe_analyzer import PEAnalyzer
    from drivertool.disassembler import Disassembler

logger = logging.getLogger(__name__)


class VulnScanner(
    ImportScanMixin,
    DeviceScanMixin,
    IOCTLScanMixin,
    MemoryScanMixin,
    ProcessScanMixin,
    EDRScanMixin,
    BinaryScanMixin,
    TaintScanMixin,
    Z3ScanMixin,
    ExploitScanMixin,
    CertScanMixin,
    YaraScanMixin,
    ScoringScanMixin,
):
    # Exploit primitive type constants
    PRIM_ARB_READ = "arbitrary-read"
    PRIM_ARB_WRITE = "arbitrary-write"
    PRIM_ARB_INC = "arbitrary-increment"
    PRIM_POOL_OVERFLOW = "pool-overflow"
    PRIM_INFO_LEAK = "info-leak"
    PRIM_CODE_EXEC = "code-execution"
    PRIM_PHYS_RW = "physical-rw"
    PRIM_MSR_RW = "msr-rw"
    PRIM_PROCESS_CTRL = "process-control"
    PRIM_PROCESS_KILL = "process-kill"
    PRIM_PROCESS_ATTACH = "process-attach"
    PRIM_THREAD_INJECT = "thread-injection"
    PRIM_TOKEN_STEAL = "token-steal"
    PRIM_TOKEN_MODIFY = "token-modify"
    PRIM_PPL_BYPASS = "ppl-bypass"
    PRIM_CALLBACK_REMOVE = "callback-removal"
    PRIM_ETW_DISABLE = "etw-disable"
    PRIM_EDR_DOWNGRADE = "edr-token-downgrade"
    PRIM_DSE_DISABLE = "dse-disable"
    PRIM_DOS = "denial-of-service"

    def __init__(self, pe: PEAnalyzer, dis: Disassembler):
        self.pe = pe
        self.dis = dis
        self.findings: List[Finding] = []
        self.ioctl_codes: List[int] = []       # all detected IOCTL codes
        self.ioctl_purposes: Dict[int, str] = {}  # code → purpose label
        # IRP major-function slot the code was observed on. 0x0D = FSCTL,
        # 0x0E = IOCTL (DEVICE_CONTROL), 0x0F = INTERNAL_DEVICE_CONTROL.
        # Populated by ioctl_scan; default reads as 0x0E.
        self.ioctl_origin_slot: Dict[int, int] = {}
        self.minifilter_ports: List[str] = []    # FltCreateCommunicationPort names
        self.hash_dispatch_codes: List[int] = []  # codes recovered via hash-dispatch reversal
        self._bruteforce_handler_map: Dict[int, int] = {}  # code → handler_va (deferred)
        self.ioctl_structs: Dict[int, List[dict]] = {}   # code → struct field list
        self.ioctl_primitives: Dict[int, List[str]] = {}  # code → exploit primitives
        # For each (ioctl_code, primitive) record the VA of the characteristic
        # API call that *implements* the primitive. Used to tell whether two
        # IOCTLs share a kill-site / token-site / arb-write-site (the same
        # underlying primitive reached through different IOCTL entries) vs
        # genuinely independent primitives.
        self.ioctl_primitive_sites: Dict[int, Dict[str, List[int]]] = {}
        # Reverse index: (primitive, call_va) → [codes]. Built after all
        # primitives are classified so the renderer can produce cross-refs.
        self.primitive_shared_sites: Dict[tuple, List[int]] = {}
        # {code: target_code} when handler is a thin wrapper that just
        # dispatches into another handler's body.
        self.ioctl_thin_wrapper_of: Dict[int, int] = {}
        # Per-driver caches shared across all handler-taint passes:
        # callee disassembly cache + TaintTracker summary cache. Cuts
        # redundant work when many handlers funnel through the same
        # internal helper.
        self._callee_disasm_cache: Dict[int, List] = {}
        self._taint_summary_cache: Dict = {}
        self.attack_score: int = 0
        self.attack_risk: str = "UNKNOWN"
        self.rop_gadgets: Dict[str, List[dict]] = {}
        self.exploit_chains: List[dict] = []
        self.state_transitions: List[dict] = []
        self.attack_sequences: List[dict] = []
        self.taint_paths: List[dict] = []
        self.z3_solutions: List[dict] = []
        self.device_access: Dict = {}
        self.ioctl_behaviors: Dict[int, dict] = {}
        self.ioctl_bug_classes: Dict[int, List[str]] = {}

    def run_all(self) -> List[Finding]:
        self.scan_imports()
        self.scan_device_creation()
        self.scan_ioctl_handler()
        self.scan_memory_patterns()
        self.scan_hardcoded_addresses()
        self.scan_process_manipulation()
        self.scan_privilege_patterns()
        self.scan_section_anomalies()
        self.scan_integer_overflow_alloc()
        self.scan_kernel_info_leak()
        self.scan_dkom_patterns()
        self.scan_double_fetch()
        self.scan_callback_bodies()
        self.scan_compiler_security()
        self.scan_arbitrary_write_gadgets()
        self.scan_kernel_stack_overflows()
        self.scan_ssdt_hooks()
        self.scan_hidden_functions()
        self.scan_taint_user_input()
        self.scan_access_control()
        self.scan_certificate()
        self.scan_load_compatibility()
        self.scan_ioctl_structures()
        self.scan_device_access_security()
        # Run behavior analysis FIRST, then token/PPL/primitives use it
        self.analyze_ioctl_behaviors()
        self.scan_token_steal()
        self.scan_ppl_bypass()
        self.scan_callback_removal()
        self.scan_etw_disable()
        self.scan_edr_token_downgrade()
        self.scan_dse_disable()
        self.classify_primitives()
        self.classify_ioctl_bugs()
        self.scan_unchecked_returns()
        self.scan_interprocedural_taint()
        self.solve_ioctl_constraints()
        self.find_rop_gadgets()
        self.build_exploit_chains()
        self.detect_state_machine()
        self.compute_attack_surface_score()
        if YARA_AVAILABLE:
            self.scan_yara()
        return self.findings
