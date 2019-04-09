#!/usr/bin/python

# Copyright 2009-2010:  dogbert <dogber1@gmail.com>
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

import os

from scripts.solver import Solver, SolverError

def decode(code):
    table1 = {'1': '3', '0': '1', '3': 'F', '2': '7', '5': 'Q', '4': 'V', '7': 'X', '6': 'G', '9': 'O', '8': 'U', 'a': 'C', 'c': 'E', 'b': 'P', 'e': 'M', 'd': 'T', 'g': 'H', 'f': '8', 'i': 'Y', 'h': 'Z', 'k': 'S', 'j': 'W', 'm': '4', 'l': 'K', 'o': 'J', 'n': '9', 'q': '5', 'p': '2', 's': 'N', 'r': 'B', 'u': 'L', 't': 'A', 'w': 'D', 'v': '6', 'y': 'I', 'x': '4', 'z': '0'}
    table2 = {'1': '3', '0': '1', '3': 'F', '2': '7', '5': 'Q', '4': 'V', '7': 'X', '6': 'G', '9': 'O', '8': 'U', 'a': 'C', 'c': 'E', 'b': 'P', 'e': 'M', 'd': 'T', 'g': 'H', 'f': '8', 'i': 'Y', 'h': 'Z', 'k': 'S', 'j': 'W', 'm': '4', 'l': 'K', 'o': 'J', 'n': '9', 'q': '5', 'p': '2', 's': 'N', 'r': 'B', 'u': 'L', 't': 'A', 'w': 'D', 'v': '6', 'y': 'I', 'x': 'R', 'z': '0'}

    password1 = ""
    password2 = ""
    for c in code:
        password1 += table1[c.lower()]
        password2 += table2[c.lower()]
    if password1 == password2:
        return password1.lower()
    else:
        return password1.lower() + " OR " + password2.lower()

def decryptHash(hash, key, rotationMatrix):
    outhash = []
    for i in range(0, len(hash)):
        outhash.append(((hash[i] << (rotationMatrix[7*key+i])) & 0xFF) | (hash[i] >> (8-rotationMatrix[7*key+i])))
    return outhash

def hpminiSolver(in_str):
    code = in_str
    password = decode(code)
    if password == "":
        raise SolverError("The password could not be calculated")
    return password

def solvers():
    return [
        Solver('Hewlett-Packard/Compaq',
               'HP/Compaq Netbook 10 character',
               ['CNU1234ABC'],
               r'^\s*\w{10}\s*$',
               hpminiSolver),
    ]

def info():
    return '\n'.join([
        "Master Password Generator for HP/Compaq Mini Netbooks",
        "Copyright (C) 2009-2010 dogbert <dogber1@gmail.com>",
        "",
        "After entering the wrong password for the third time, you will receive a",
        "code from which the password can be calculated,",
        "e.g. CNU1234ABC",
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
