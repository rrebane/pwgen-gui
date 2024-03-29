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

# someone smacked his head onto the keyboard
XORkey = "<7#&9?>s"

def codeToBytes(code):
    numbers = (int(code[0:5]), int(code[5:10]), int(code[10:15]), int(code[15:20]))
    bytes = []
    for i in numbers:
        bytes.append(i % 256)
        bytes.append(i // 256)
    return bytes

def byteToChar(byte):
    if byte > 9:
        return chr(ord('a') + byte - 10)
    else:
        return chr(ord('0') + byte)

def decryptCode(bytes):
    # swap two bytes
    #bytes[2], bytes[6] = bytes[6], bytes[2]
    #bytes[3], bytes[7] = bytes[7], bytes[3]

    # interleave the nibbles
    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7] = ((bytes[3] & 0xF0) | (bytes[0]  & 0x0F), (bytes[2] & 0xF0) | (bytes[1] & 0x0F), (bytes[5] & 0xF0) | (bytes[6] & 0x0F), (bytes[4] & 0xF0) | (bytes[7] & 0x0F), (bytes[7] & 0xF0) | (bytes[4] & 0x0F), (bytes[6] & 0xF0) | (bytes[5] & 0x0F), (bytes[1] & 0xF0)  | (bytes[2] & 0x0F), (bytes[0] & 0xF0) | (bytes[3] & 0x0F))

    # apply XOR key
    for i in range(len(bytes)):
        bytes[i] = bytes[i] ^ ord(XORkey[i])

    # final rotations
    bytes[0] = ((bytes[0] << 1) & 0xFF) | (bytes[0] >> 7)
    bytes[1] = ((bytes[1] << 7) & 0xFF) | (bytes[1] >> 1)
    bytes[2] = ((bytes[2] << 2) & 0xFF) | (bytes[2] >> 6)
    bytes[3] = ((bytes[3] << 8) & 0xFF) | (bytes[3] >> 0)
    bytes[4] = ((bytes[4] << 3) & 0xFF) | (bytes[4] >> 5)
    bytes[5] = ((bytes[5] << 6) & 0xFF) | (bytes[5] >> 2)
    bytes[6] = ((bytes[6] << 4) & 0xFF) | (bytes[6] >> 4)
    bytes[7] = ((bytes[7] << 5) & 0xFF) | (bytes[7] >> 3)

    # len(solution space) = 10+26
    bytes = [x % 36 for x in bytes]

    masterPwd = ""
    for x in bytes:
        masterPwd += byteToChar(x)
    return masterPwd

def fsi6x4Solver(in_str):
    in_str = in_str.strip().replace('-', '').replace(' ', '')
    in_str = in_str[4:]
    return decryptCode(codeToBytes(in_str))

def solvers():
    return [
        Solver('Fujitsu-Siemens',
               'Fujitsu-Siemens 6x4 decimal',
               ['8F16-1234-4321-1234-4321-1234'],
               r'^\s*\w{4}-\d{4}-\d{4}-\d{4}-\d{4}-\d{4}\s*$',
               fsi6x4Solver),
    ]

def info():
    return '\n'.join([
        "Master Password Generator for FSI laptops (6x4 digits version)",
        "Copyright (C) 2013 dogbert <dogber1@gmail.com>",
        "",
        "When asked for a password, enter these:",
        "First password:  3hqgo3",
        "Second password: jqw534",
        "Third password:  0qww294e",
        "",
        "You will receive a hash code with five blocks, each with four numbers,",
        "e.g. 1234-4321-1234-4321-1234",
        "",
        "Please note that the password is encoded for US QWERTY keyboard layouts.",
    ])

def run(in_str = None):
    if in_str is None:
        print(info())
        in_str = input("Please enter the hash: ")

    found_solver = False
    for solver in solvers():
        if solver.is_valid_input(in_str):
            password = solver.solve(in_str)
            print('{}: {}'.format(solver.description, password))

    if not found_solver:
        print("No solver for given input")

if __name__ == "__main__":
    run()
