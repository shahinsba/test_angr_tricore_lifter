#!/usr/bin/env python3
"""
Test module for angr tricore lifter.

Usage: python3 test.py
"""

import sys
import os
import unittest
import binascii
import struct
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

    def test_rc_instructions(self):
        """ Test instructions with RC format. """

        # iterate through instruction formats
        for instr_frmt in instructions:

            if instr_frmt != "RC_format":
                # skip formats except RC
                continue

            print("\n", "="*50)
            print("= {0} instructions".format(instr_frmt))
            print("="*50)

            # iterate through instructions
            num_instructions = 0
            num_testcases = 0
            for item in instructions[instr_frmt]:
                num_instructions += 1
                ins_name = item['instruction'][0]['name']
                ins_asm = item['instruction'][1]['asm']
                ins_hex = item['instruction'][2]['hex']

                print("\n", "-"*50)
                print("---- Test cases for '{0}'".format(ins_name))
                print("---- {0}\n".format(ins_asm))

                # continue if there is no test case
                if item['instruction'][3]['testcases'] is None:
                    continue

                # iterate through testcases
                testcase_counter = 1
                for testcase in item['instruction'][3]['testcases']:
                    case_item = 'case{0}'.format(testcase_counter)
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
                                        state.mem[adr_1].uint32_t = struct.unpack("<I", struct.pack(">I", val_1))[0]
                                        state.mem[adr_2].uint32_t = struct.unpack("<I", struct.pack(">I", val_2))[0]
                                    else:
                                        state.mem[int(reg[1:-1], 16)].uint32_t = struct.unpack("<I", struct.pack(">I",
                                                                                                                val))[0]
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
                                        mem_val = get_mem_val(sm.active[0], int(reg[1:-1], 16),size)
                                        self.assertEqual(mem_val, val)
                                    else:
                                        reg_val = get_reg_val(sm.active[0], reg)
                                        reg_val &= 0xffffffff  # get 32-bit value
                                        self.assertEqual(reg_val, val)
                        else:
                            print("Result is empty!")
                    else:
                        print("No Stash!")
                        print("Check the following:")
                        print("  - if instruction '{0}' has been added to lift_tricore module.".format(ins_name))
                        print("  - if opcode of '{0}' is correct in its class.".format(ins_name))
                        sys.exit(1)

                    testcase_counter += 1
                    num_testcases += 1

            print("{0} testcases passed for {1} {2} instruction(s)".format(num_testcases,num_instructions,instr_frmt))

if __name__ == '__main__':
    unittest.main()
