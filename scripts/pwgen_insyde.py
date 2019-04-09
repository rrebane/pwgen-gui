#!/usr/bin/python

# Copyright 2011: dogbert <dogber1@gmail.com>
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

def calcPassword(strHash):
    salt = 'Iou|hj&Z'

    pwd = ""
    for i in range(0, 8):
        b = ord(salt[i]) ^ ord(strHash[i])
        a = b
        a = (a * 0x66666667) >> 32
        a = (a >> 2) | (a & 0xC0)
        if ( a & 0x80000000 ):
            a += 1
        a *= 10
        pwd += str(b-a)
    return pwd

def insydeSolver(in_str):
    in_str = in_str.strip().replace('-', '')
    return calcPassword(in_str)

def solvers():
    return [
        Solver('Insyde H20 (generic)',
               'Insyde H20 (generic) 8 decimal digits',
               ['03133610'],
               r'^\s*\d{8}\s*$',
               insydeSolver),
    ]

def info():
    return '\n'.join([
        "Master Password Generator for InsydeH2O BIOS (Acer, HP laptops)",
        "Copyright (C) 2009-2011 dogbert <dogber1@gmail.com>",
        "",
        "Enter three invalid passwords. You will receive a hash code consisting",
        "out of eight numbers ",
        "e.g. 03133610",
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
