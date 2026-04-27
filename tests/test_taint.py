"""Unit tests for the TaintTracker."""

import unittest

import capstone.x86_const as x86c

from drivertool.taint import TaintTracker


class MockOperand:
    """Minimal stand-in for a Capstone operand."""

    def __init__(self, op_type, reg=0, imm=0, mem_base=0, mem_index=0, mem_disp=0):
        self.type = op_type
        self.reg = reg
        self.imm = imm
        self.mem = type("Mem", (), {
            "base": mem_base,
            "index": mem_index,
            "disp": mem_disp,
            "scale": 1,
        })()


class MockInsn:
    """Minimal stand-in for a Capstone instruction."""

    def __init__(self, addr, mnemonic, operands):
        self.address = addr
        self.mnemonic = mnemonic
        self.operands = operands
        self.size = 3  # arbitrary
        self.op_str = ""


class TestTaintTracker(unittest.TestCase):
    """Tests for forward taint propagation."""

    def _make(self, iat_map=None, resolve=None):
        return TaintTracker(iat_map or {}, resolve, max_call_depth=2)

    def test_mov_propagates_taint(self):
        tracker = self._make()
        insns = [
            MockInsn(0x1000, "mov", [
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RDX),
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RCX),
            ]),
        ]
        hits = tracker.analyze(insns, {x86c.X86_REG_RCX})
        self.assertEqual(len(hits), 0)
        # rdx should now be tainted; verify by sending it to a sink
        insns2 = [
            MockInsn(0x1000, "mov", [
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RDX),
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RCX),
            ]),
            MockInsn(0x1003, "call", [
                MockOperand(x86c.X86_OP_IMM, imm=0x4000),
            ]),
        ]
        hits2 = tracker.analyze(insns2, {x86c.X86_REG_RCX})
        # No IAT hit because 0x4000 is not in iat_map
        self.assertEqual(len(hits2), 0)

    def test_xor_zeroing_clears_taint(self):
        tracker = self._make()
        insns = [
            MockInsn(0x1000, "xor", [
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RAX),
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RAX),
            ]),
            MockInsn(0x1003, "call", [
                MockOperand(x86c.X86_OP_IMM, imm=0x4000),
            ]),
        ]
        hits = tracker.analyze(insns, {x86c.X86_REG_RAX})
        self.assertEqual(len(hits), 0)

    def test_iat_sink_with_tainted_arg(self):
        tracker = self._make(iat_map={0x4000: "ZwTerminateProcess"})
        insns = [
            MockInsn(0x1000, "mov", [
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RDX),
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RCX),
            ]),
            MockInsn(0x1003, "call", [
                MockOperand(x86c.X86_OP_IMM, imm=0x4000),
            ]),
        ]
        # rcx is tainted, so after mov, rdx is tainted.
        # ZwTerminateProcess arg2 (rdx) is tainted.
        hits = tracker.analyze(insns, {x86c.X86_REG_RCX})
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["func"], "ZwTerminateProcess")
        self.assertIn(1, hits[0]["tainted_args"])  # arg index 1 = rdx

    def test_call_clears_volatiles(self):
        tracker = self._make(iat_map={0x4000: "ZwOpenProcess"})
        insns = [
            MockInsn(0x1000, "call", [
                MockOperand(x86c.X86_OP_IMM, imm=0x4000),
            ]),
        ]
        # rcx is tainted before call, but call clobbers volatile regs
        hits = tracker.analyze(insns, {x86c.X86_REG_RCX})
        # After the call, rcx is no longer tainted, so the *next* call wouldn't
        # report it. However, the call instruction itself checks args BEFORE
        # clobbering, so this hit should still be recorded.
        self.assertEqual(len(hits), 1)

    def test_interprocedural_summary(self):
        # Callee makes an IAT call with arg0 (rcx) tainted.
        # TaintTracker marks ret_tainted=True when arg0 is tainted at an
        # IAT call inside the callee. The caller then sees RAX as tainted.
        callee_insns = [
            MockInsn(0x2000, "call", [
                MockOperand(x86c.X86_OP_IMM, imm=0x5000),
            ]),
            MockInsn(0x2003, "mov", [
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RAX),
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RCX),
            ]),
            MockInsn(0x2006, "ret", []),
        ]

        def _resolve(va):
            return callee_insns if va == 0x2000 else None

        iat = {
            0x4000: "ZwTerminateProcess",
            0x5000: "ZwOpenProcess",  # callee hits this with tainted rcx
        }
        tracker = self._make(iat_map=iat, resolve=_resolve)

        # Caller calls callee, then moves rax->rcx and calls sink
        insns = [
            MockInsn(0x1000, "call", [
                MockOperand(x86c.X86_OP_IMM, imm=0x2000),
            ]),
            MockInsn(0x1003, "mov", [
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RCX),
                MockOperand(x86c.X86_OP_REG, reg=x86c.X86_REG_RAX),
            ]),
            MockInsn(0x1006, "call", [
                MockOperand(x86c.X86_OP_IMM, imm=0x4000),
            ]),
        ]
        hits = tracker.analyze(insns, {x86c.X86_REG_RCX})
        # We expect 2 hits:
        # 1. callee's call to ZwOpenProcess with tainted rcx
        # 2. caller's call to ZwTerminateProcess with tainted rcx (via rax)
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0]["func"], "ZwOpenProcess")
        self.assertEqual(hits[1]["func"], "ZwTerminateProcess")
        self.assertIn(0, hits[1]["tainted_args"])


if __name__ == "__main__":
    unittest.main()
