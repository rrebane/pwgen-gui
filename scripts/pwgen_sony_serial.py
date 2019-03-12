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

def getMasterPwd(serial):
    if len(serial) != 7:
        print("The serial must be exactly 7 characters in length!")
        return

    table = "0987654321876543210976543210982109876543109876543221098765436543210987"
    pos = 0
    code = ""
    for c in serial:
        code += table[int(c)+10*pos]
        pos += 1
    return code

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

    code = in_str
    password = getMasterPwd(code)
    if password:
        print(("The password is: " + password))

if __name__ == "__main__":
    run()
