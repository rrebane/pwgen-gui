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
import os, struct

from scripts.solver import Solver, SolverError

def getMasterPwd(serial):
    if len(serial) != 7:
        raise SolverError("The serial must be exactly 7 characters in length!")

    table = "0987654321876543210976543210982109876543109876543221098765436543210987"
    pos = 0
    code = ""
    for c in serial:
        code += table[int(c)+10*pos]
        pos += 1

    return code

def sonySolver(in_str):
    in_str = in_str.strip()
    return getMasterPwd(in_str)

def solvers():
    return [
        Solver('Sony',
               'Sony 7 decimal digits',
               ['1234567'],
               r'^\s*\d{7}\s*$',
               sonySolver),
    ]

def info():
    return '\n'.join([
        "Master Password Generator for Sony laptops (serial number)",
        "Copyright (C) 2009-2010 dogbert <dogber1@gmail.com>",
        "",
        "This script generates master passwords for old Sony laptops from their serial ",
        "number.",
    ])

def run(in_str = None):
    if in_str is None:
        print(info())
        in_str = input("Please enter the serial number: ")

    found_solver = False
    for solver in solvers():
        if solver.is_valid_input(in_str):
            password = solver.solve(in_str)
            print('{}: {}'.format(solver.description, password))

    if not found_solver:
        print("No solver for given input")

if __name__ == "__main__":
    run()
