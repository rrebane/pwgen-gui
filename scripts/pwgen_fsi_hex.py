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
#
# This script generates master passwords which can be used to unlock
# the BIOS passwords of most Fujitsu Siemens laptops (Lifebook, Amilo etc.).
# You have to install python for running this script.

import os

from scripts.solver import Solver, SolverError

# d'oh
def generateCRC16Table():
    table = []
    for i in range(0, 256):
        crc = (i << 8)
        for j in range(0, 8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = (crc << 1)
        table.append(crc & 0xFFFF)
    return table

# D'OH
def calculateHash(word, table):
    hash = 0
    for c in word:
        d = table[(ord(c) ^ (hash >> 8)) % 256]
        hash = ((hash << 8) ^ d) & 0xFFFF
    return hash

def hashToString(hash):
    return (chr(ord('0') + ((hash>>12) % 16) % 10) + chr(ord('0') + ((hash>>8) % 16) % 10) + chr(ord('0') + ((hash>>4) % 16) % 10)  + chr(ord('0') + ((hash>>0) % 16) % 10))

def decryptCode(code, table):
    return hashToString(calculateHash(code[0:4], table)) + hashToString(calculateHash(code[4:8], table))

def fsi5x4HexSolver(in_str):
    in_str = in_str.replace('-', '')
    if len(in_str) == 20:
        in_str = in_str[12:20]
    table = generateCRC16Table()
    return decryptCode(in_str.upper(), table)


def solvers():
    return [
        Solver('Fujitsu-Siemens',
               'Fujitsu-Siemens 5x4 hexadecimal',
               ['AAAA-BBBB-CCCC-DEAD-BEEF'],
               r'^\s*[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}\s*$',
               fsi5x4HexSolver),
    ]

def info():
    return '\n'.join([
        "Master Password Generator for FSI laptops (hexadecimal digits version)",
        "Copyright (C) 2009 dogbert <dogber1@gmail.com>",
        "",
        "After entering the wrong password for the third time, you will receive a",
        "hexadecimal code from which the master password can be calculated,",
        "e.g. 0A1B2D3E or AAAA-BBBB-CCCC-DEAD-BEEF",
    ])

def run(in_str = None):
    if in_str is None:
        print(info())
        in_str = input("Please enter the code: ")

    found_solver = False
    for solver in solvers():
        if solver.is_valid_input(in_str):
            password = solver.solve(in_str)
            print('{}: {}'.format(solver.description, password))

    if not found_solver:
        print("No solver for given input")

if __name__ == "__main__":
    run()
