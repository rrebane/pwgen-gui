#!/usr/bin/python

# Copyright 2009:  dogbert <dogber1@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

# This script generates master passwords which can be used to unlock the BIOS
# password of most Phoenix BIOS versions. It also works for some versions of
# FSI, HP and Compaq laptops which use slightly different hashing algorithms
# in the BIOS.
# You have to install python 2.x for running this script.

import functools
import os, random

from scripts.solver import Solver, SolverError

KEYBOARD_DICT = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11:
    '0', 16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i',
    24: 'o', 25: 'p', 30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36:
    'j', 37: 'k', 38: 'l', 44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n',
    50: 'm'
}

def keyboardEncToAscii(inKey):
    out = ""
    for c in inKey:
        if c != 0:
            out += KEYBOARD_DICT[c]
    return out

def asciiToKeyboardenc(inAscii):
    out = []
    asciiDict = dict([(a, k) for k,a in KEYBOARD_DICT.items()])
    for c in inAscii:
        if c != 0:
            out.append(asciiDict[c])
    return out


# The phoenix implementation of the CRC-16 contains a rather severe bug
# quartering the image space of the function: both the first and second MSB
# are always zero regardless of the input.
# For a working implementation, you'd have to change the polynom from 0x2001
# to e.g. 0xA001.
def badCRC16(pwd, salt=0):
    hash = salt
    for c in pwd:
        hash = hash ^ c
        for i in range(0, 8):
            if (hash & 1):
                hash = (hash >> 1) ^ 0x2001
            else:
                hash = (hash >> 1)
    return hash


def bruteForce(hash, salt=0, digitsOnly=False, charsOnly=True, minLen=3, maxLen=8):
    global KEYBOARD_DICT
    KEYBOARD_DICTOrig = KEYBOARD_DICT
    if digitsOnly:
        KEYBOARD_DICT = dict(list(zip(list(KEYBOARD_DICT.keys())[0:9],list(KEYBOARD_DICT.values())[0:9])))
    elif charsOnly:
        KEYBOARD_DICT = dict(list(zip(list(KEYBOARD_DICT.keys())[10:36],list(KEYBOARD_DICT.values())[10:36])))

    encodedPwd = []
    for i in range(0, 7):
        encodedPwd.append(list(KEYBOARD_DICT.keys())[0])
    random.seed()
    if hash > 0x3FFF:
        return "invalid hash code"
    while 1:
        # generate random password
        rndVal = random.random()*len(KEYBOARD_DICT)
        for i in range(0,len(encodedPwd)):
            value = int(rndVal % len(KEYBOARD_DICT))
            encodedPwd[i] = list(KEYBOARD_DICT.keys())[value]
            rndVal = rndVal * len(KEYBOARD_DICT)
        # test substrings of the random password
        for i in range(minLen, maxLen+1):
            if badCRC16(encodedPwd[0:i], salt) == hash:
                KEYBOARD_DICT = KEYBOARD_DICTOrig
                encodedPwd = encodedPwd[0:i]
                return keyboardEncToAscii(encodedPwd[0:i])

def generateSolver(func, hash_plus=0):
    def solve(in_str):
        code = in_str.replace('[', '').replace(']', '')
        hash = int(code)
        return func(hash + hash_plus)
    return solve

def solvers():
    return [
        # bruteForce(hash, 0)
        Solver('Phoenix (generic)',
               'Phoenix (generic)',
               ['12345'],
               r'^\s*\d{5}\s*$',
               generateSolver(bruteForce)),
        # bruteForce(hash, salt=17232)
        Solver('Hewlett-Packard/Compaq',
               'HP/Compaq Phoenix',
               ['12345'],
               r'^\s*\d{5}\s*$',
               generateSolver(functools.partial(bruteForce, salt=17232))),
        # bruteForce(hash, salt=65, minLen=3, maxLen=7, digitsOnly=True)
        Solver('Fujitsu-Siemens',
               'Fujitsu-Siemens (generic) Phoenix',
               ['12345'],
               r'^\s*\d{5}\s*$',
               generateSolver(functools.partial(bruteForce, salt=65, minLen=3,
                                                maxLen=7, digitsOnly=True))),
        # bruteForce(hash+1, salt=ord('L'), minLen=3, maxLen=7, digitsOnly=True)
        Solver('Fujitsu-Siemens',
               'Fujitsu-Siemens (\'L\' model) Phoenix',
               ['12345'],
               r'^\s*\d{5}\s*$',
               generateSolver(functools.partial(bruteForce, salt=ord('L'),
                                                minLen=3, maxLen=7,
                                                digitsOnly=True),
                              hash_plus=1)),
        # bruteForce(hash+1, salt=ord('P'), minLen=3, maxLen=7, digitsOnly=True)
        Solver('Fujitsu-Siemens',
               'Fujitsu-Siemens (\'P\' model) Phoenix',
               ['12345'],
               r'^\s*\d{5}\s*$',
               generateSolver(functools.partial(bruteForce, salt=ord('P'),
                                                minLen=3, maxLen=7,
                                                digitsOnly=True),
                              hash_plus=1)),
        # bruteForce(hash+1, salt=ord('S'), minLen=3, maxLen=7, digitsOnly=True)
        Solver('Fujitsu-Siemens',
               'Fujitsu-Siemens (\'S\' model) Phoenix',
               ['12345'],
               r'^\s*\d{5}\s*$',
               generateSolver(functools.partial(bruteForce, salt=ord('S'),
                                                minLen=3,
                                                maxLen=7, digitsOnly=True),
                              hash_plus=1)),
        # bruteForce(hash+1, salt=ord('X'), minLen=3, maxLen=7, digitsOnly=True)
        Solver('Fujitsu-Siemens',
               'Fujitsu-Siemens (\'X\' model) Phoenix',
               ['12345'],
               r'^\s*\d{5}\s*$',
               generateSolver(functools.partial(bruteForce, salt=ord('X'),
                                                minLen=3, maxLen=7,
                                                digitsOnly=True),
                              hash_plus=1)),
    ]

def info():
    return '\n'.join([
        "Master Password Generator for Phoenix BIOS (five decimal digits version)",
        "Copyright (C) 2009 dogbert <dogber1@gmail.com>",
        "",
        "After entering the wrong password for the third time, you will receive a",
        "decimal number from which the master password can be calculated,",
        "e.g. 12345",
        "",
        "Please note that the password has been encoded for the standard US",
        "keyboard layout (QWERTY).",
    ])

def run(in_str = None):
    if in_str is None:
        print(info())
        in_str = input("Please enter the number: ")

    found_solver = False
    for solver in solvers():
        if solver.is_valid_input(in_str):
            password = solver.solve(in_str)
            print('{}: {}'.format(solver.description, password))

    if not found_solver:
        print("No solver for given input")

if __name__ == "__main__":
    run()
