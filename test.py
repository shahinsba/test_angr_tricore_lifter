#!/usr/bin/env python3
""" Test module for angr tricore lifter.
Usage: python3 test.py
"""

import sys
import os
import unittest
import binascii
import yaml
import angr
from angr_platforms.tricore import LifterTRICORE  # pylint: disable=[unused-import]

TEST_FILE = "./testcases.yaml"
if not os.path.exists(TEST_FILE):
    print("Error: test file not found!")
    sys.exit(1)

ALL_REGS = ["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8","d9", "d10",
            "d11", "d12", "d13", "d14", "d15",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8","a9", "a10",
            "a11", "a12", "a13", "a14", "a15",
            "psw", "pc", "fcx", "pcxi"]

def get_reg_val(state, regname):
    if regname == "d0":
        return state.solver.eval(state.regs.d0)
    elif regname == "d1":
        return state.solver.eval(state.regs.d1)
    elif regname == "d2":
        return state.solver.eval(state.regs.d2)
    elif regname == "d3":
        return state.solver.eval(state.regs.d3)
    elif regname == "d4":
        return state.solver.eval(state.regs.d4)
    elif regname == "d5":
        return state.solver.eval(state.regs.d5)
    elif regname == "d6":
        return state.solver.eval(state.regs.d6)
    elif regname == "d7":
        return state.solver.eval(state.regs.d7)
    elif regname == "d8":
        return state.solver.eval(state.regs.d8)
    elif regname == "d9":
        return state.solver.eval(state.regs.d9)
    elif regname == "d10":
        return state.solver.eval(state.regs.d10)
    elif regname == "d11":
        return state.solver.eval(state.regs.d11)
    elif regname == "d12":
        return state.solver.eval(state.regs.d12)
    elif regname == "d13":
        return state.solver.eval(state.regs.d13)
    elif regname == "d14":
        return state.solver.eval(state.regs.d14)
    elif regname == "d15":
        return state.solver.eval(state.regs.d15)
    elif regname == "a0":
        return state.solver.eval(state.regs.a0)
    elif regname == "a1":
        return state.solver.eval(state.regs.a1)
    elif regname == "a2":
        return state.solver.eval(state.regs.a2)
    elif regname == "a3":
        return state.solver.eval(state.regs.a3)
    elif regname == "a4":
        return state.solver.eval(state.regs.a4)
    elif regname == "a5":
        return state.solver.eval(state.regs.a5)
    elif regname == "a6":
        return state.solver.eval(state.regs.a6)
    elif regname == "a7":
        return state.solver.eval(state.regs.a7)
    elif regname == "a8":
        return state.solver.eval(state.regs.a8)
    elif regname == "a9":
        return state.solver.eval(state.regs.a9)
    elif regname == "a10":
        return state.solver.eval(state.regs.a10)
    elif regname == "a11":
        return state.solver.eval(state.regs.a11)
    elif regname == "a12":
        return state.solver.eval(state.regs.a12)
    elif regname == "a13":
        return state.solver.eval(state.regs.a13)
    elif regname == "a14":
        return state.solver.eval(state.regs.a14)
    elif regname == "a15":
        return state.solver.eval(state.regs.a15)
    elif regname == "pc":
        return state.solver.eval(state.regs.pc)
    elif regname == "psw":
        return state.solver.eval(state.regs.psw)
    elif regname == "fcx":
        return state.solver.eval(state.regs.fcx)

    return None

def get_mem_val(state, addr, size):
    return state.solver.eval(state.memory.load(addr, size, endness="Iend_LE"), cast_to=int)

def change_to_LE(val):
    """ change endianess to LE. """
    result = ((val         & 0xff) << 24) | \
             (((val >> 8)  & 0xff) << 16) | \
             (((val >> 16) & 0xff) << 8)  | \
             ((val >> 24)  & 0xff)
    return result

# read test file
with open(TEST_FILE, "rb") as stream:
    try:
        data = yaml.safe_load(stream)
    except yaml.YAMLError as e:
        print(e)
        sys.exit(1)
instructions = data['instructions']

class TestTricoreLifter(unittest.TestCase):
    """ Class for testing tricore lifter.  """

    def run_tests(self, tests):
        """ Run tests. """
        # iterate through test instructions
        for item in tests:
            ins_name = item['instruction'][0]['name']
            ins_asm = item['instruction'][1]['asm']
            ins_hex = item['instruction'][2]['hex']

            print("\n", "-"*50,
                  "\n---- Test cases for '{0}'".format(ins_name),
                  "\n---- {0}\n".format(ins_asm))

            # continue if the instruction has no test case
            if item['instruction'][3]['testcases'] is None:
                continue

            # iterate through testcases
            testcase_counter = 1
            for testcase in item['instruction'][3]['testcases']:
                case_item = 'case{0}'.format(testcase_counter)
                testcase_counter += 1
                print("---- {0}: {1}\n".format(case_item, testcase[case_item][2]['desc']))

                p = angr.load_shellcode(binascii.unhexlify(ins_hex),
                                        'tricore',
                                        start_offset=0,
                                        load_address=0)
                state = p.factory.entry_state()

                # reset registers
                for reg in ALL_REGS:
                    setattr(state.regs, reg, 0)

                # apply preconditions
                if testcase[case_item][0]['preconditions']:
                    for precondition in testcase[case_item][0]['preconditions']:
                        for reg, val in precondition.items():
                            if reg[:1] == "[":
                                if len(hex(val)[2:]) > 8:  # for 64-bit values
                                    adr_1 = int(reg[1:-1], 16)
                                    adr_2 = adr_1 + 4
                                    val_1 = val & 0xffffffff
                                    val_2 = val >> 32
                                    state.mem[adr_1].uint32_t = change_to_LE(val_1)
                                    state.mem[adr_2].uint32_t = change_to_LE(val_2)
                                else:
                                    state.mem[int(reg[1:-1], 16)].uint32_t = change_to_LE(val)
                            else:
                                setattr(state.regs, reg, val)

                # run simulation
                sm = p.factory.simulation_manager(state)
                sm.explore(n=1)

                # check result
                if len(sm.active) > 0:
                    if testcase[case_item][1]['result']:
                        for result in testcase[case_item][1]['result']:
                            for reg, val in result.items():
                                if reg[:1] == "[":
                                    size = 4
                                    mem_val = get_mem_val(sm.active[0], int(reg[1:-1], 16), size)
                                    self.assertEqual(hex(mem_val), hex(val))
                                else:
                                    reg_val = get_reg_val(sm.active[0], reg)
                                    reg_val &= 0xffffffff  # get 32-bit value
                                    self.assertEqual(hex(reg_val), hex(val))
                    else:
                        print("Result is empty!")
                else:
                    print("No Stash!")
                    print("Check the following:")
                    print("  - if instruction '{0}' has been added to lift_tricore module.".format(ins_name))
                    print("  - if opcode of '{0}' is correct in its class.".format(ins_name))
                    sys.exit(1)

    def test_abs_instructions(self):
        """ Test instructions with ABS format. """
        print("\n", "="*20, "Testing {0} ABS format instructions".format(len(instructions['ABS_format'])), "="*20)
        self.run_tests(instructions['ABS_format'])

    def test_absb_instructions(self):
        """ Test instructions with ABSB format. """
        print("\n", "="*20, "Testing {0} ABSB format instructions".format(len(instructions['ABSB_format'])), "="*20)
        self.run_tests(instructions['ABSB_format'])

    def test_bit_instructions(self):
        """ Test instructions with BIT format. """
        print("\n", "="*20, "Testing {0} BIT format instructions".format(len(instructions['BIT_format'])), "="*20)
        self.run_tests(instructions['BIT_format'])

    def test_bo_instructions(self):
        """ Test instructions with BO format. """
        print("\n", "="*20, "Testing {0} BO format instructions".format(len(instructions['BO_format'])), "="*20)
        self.run_tests(instructions['BO_format'])

    def test_bol_instructions(self):
        """ Test instructions with BOL format. """
        print("\n", "="*20, "Testing {0} BOL format instructions".format(len(instructions['BOL_format'])), "="*20)
        self.run_tests(instructions['BOL_format'])

    def test_rc_instructions(self):
        """ Test instructions with RC format. """
        print("\n", "="*20, "Testing {0} RC format instructions".format(len(instructions['RC_format'])), "="*20)
        self.run_tests(instructions['RC_format'])

    def test_rcpw_instructions(self):
        """ Test instructions with RCPW format. """
        print("\n", "="*20, "Testing {0} RCPW format instructions".format(len(instructions['RCPW_format'])), "="*20)
        self.run_tests(instructions['RCPW_format'])

    def test_rcr_instructions(self):
        """ Test instructions with RCR format. """
        print("\n", "="*20, "Testing {0} RCR format instructions".format(len(instructions['RCR_format'])), "="*20)
        self.run_tests(instructions['RCR_format'])

    def test_rcrr_instructions(self):
        """ Test instructions with RCRR format. """
        print("\n", "="*20, "Testing {0} RCRR format instructions".format(len(instructions['RCRR_format'])), "="*20)
        self.run_tests(instructions['RCRR_format'])

    def test_rlc_instructions(self):
        """ Test instructions with RLC format. """
        print("\n", "="*20, "Testing {0} RLC format instructions".format(len(instructions['RLC_format'])), "="*20)
        self.run_tests(instructions['RLC_format'])

    def test_rr_instructions(self):
        """ Test instructions with RR format. """
        print("\n", "="*20, "Testing {0} RR format instructions".format(len(instructions['RR_format'])), "="*20)
        self.run_tests(instructions['RR_format'])

    def test_rr1_instructions(self):
        """ Test instructions with RR1 format. """
        print("\n", "="*20, "Testing {0} RR1 format instructions".format(len(instructions['RR1_format'])), "="*20)
        self.run_tests(instructions['RR1_format'])

    def test_rr2_instructions(self):
        """ Test instructions with RR2 format. """
        print("\n", "="*20, "Testing {0} RR2 format instructions".format(len(instructions['RR2_format'])), "="*20)
        self.run_tests(instructions['RR2_format'])

    def test_rrpw_instructions(self):
        """ Test instructions with RRPW format. """
        print("\n", "="*20, "Testing {0} RRPW format instructions".format(len(instructions['RRPW_format'])), "="*20)
        self.run_tests(instructions['RRPW_format'])

    def test_rrr_instructions(self):
        """ Test instructions with RRR format. """
        print("\n", "="*20, "Testing {0} RRR format instructions".format(len(instructions['RRR_format'])), "="*20)
        self.run_tests(instructions['RRR_format'])

    def test_rrr1_instructions(self):
        """ Test instructions with RRR1 format. """
        print("\n", "="*20, "Testing {0} RRR1 format instructions".format(len(instructions['RRR1_format'])), "="*20)
        self.run_tests(instructions['RRR1_format'])

    def test_rrr2_instructions(self):
        """ Test instructions with RRR2 format. """
        print("\n", "="*20, "Testing {0} RRR2 format instructions".format(len(instructions['RRR2_format'])), "="*20)
        self.run_tests(instructions['RRR2_format'])

    def test_rrrr_instructions(self):
        """ Test instructions with RRRR format. """
        print("\n", "="*20, "Testing {0} RRRR format instructions".format(len(instructions['RRRR_format'])), "="*20)
        self.run_tests(instructions['RRRR_format'])

    def test_rrrw_instructions(self):
        """ Test instructions with RRRW format. """
        print("\n", "="*20, "Testing {0} RRRW format instructions".format(len(instructions['RRRW_format'])), "="*20)
        self.run_tests(instructions['RRRW_format'])

    def test_sc_instructions(self):
        """ Test instructions with SC format. """
        print("\n", "="*20, "Testing {0} SC format instructions".format(len(instructions['SC_format'])), "="*20)
        self.run_tests(instructions['SC_format'])

    def test_slr_instructions(self):
        """ Test instructions with SLR format. """
        print("\n", "="*20, "Testing {0} SLR format instructions".format(len(instructions['SLR_format'])), "="*20)
        self.run_tests(instructions['SLR_format'])

    def test_slro_instructions(self):
        """ Test instructions with SLRO format. """
        print("\n", "="*20, "Testing {0} SLRO format instructions".format(len(instructions['SLRO_format'])), "="*20)
        self.run_tests(instructions['SLRO_format'])

    def test_sr_instructions(self):
        """ Test instructions with SR format. """
        print("\n", "="*20, "Testing {0} SR format instructions".format(len(instructions['SR_format'])), "="*20)
        self.run_tests(instructions['SR_format'])

    def test_src_instructions(self):
        """ Test instructions with SRC format. """
        print("\n", "="*20, "Testing {0} SRC format instructions".format(len(instructions['SRC_format'])), "="*20)
        self.run_tests(instructions['SRC_format'])

    def test_sro_instructions(self):
        """ Test instructions with SRO format. """
        print("\n", "="*20, "Testing {0} SRO format instructions".format(len(instructions['SRO_format'])), "="*20)
        self.run_tests(instructions['SRO_format'])

    def test_srr_instructions(self):
        """ Test instructions with SRR format. """
        print("\n", "="*20, "Testing {0} SRR format instructions".format(len(instructions['SRR_format'])), "="*20)
        self.run_tests(instructions['SRR_format'])

    def test_srrs_instructions(self):
        """ Test instructions with SRRS format. """
        print("\n", "="*20, "Testing {0} SRRS format instructions".format(len(instructions['SRRS_format'])), "="*20)
        self.run_tests(instructions['SRRS_format'])

    def test_ssr_instructions(self):
        """ Test instructions with SSR format. """
        print("\n", "="*20, "Testing {0} SSR format instructions".format(len(instructions['SSR_format'])), "="*20)
        self.run_tests(instructions['SSR_format'])

    def test_ssro_instructions(self):
        """ Test instructions with SSRO format. """
        print("\n", "="*20, "Testing {0} SSRO format instructions".format(len(instructions['SSRO_format'])), "="*20)
        self.run_tests(instructions['SSRO_format'])

    def test_sys_instructions(self):
        """ Test instructions with SYS format. """
        print("\n", "="*20, "Testing {0} SYS format instructions".format(len(instructions['SYS_format'])), "="*20)
        self.run_tests(instructions['SYS_format'])

if __name__ == '__main__':
    unittest.main()
