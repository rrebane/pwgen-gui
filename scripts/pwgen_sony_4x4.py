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

otpChars = "9DPK7V2F3RT6HX8J"
pwdChars = "47592836"

def decodeHash(hashCode):
    s = bytearray(len(hashCode) // 2)
    for i in range(len(s)):
        s[len(s) - i - 1] = otpChars.find(hashCode[i * 2]) * 16 + otpChars.find(hashCode[i * 2 + 1])
    return s

def encodePassword(d):
    n = struct.unpack("<I", d[0:4])[0]
    p = ""
    for i in range(8):
        p += pwdChars[(n >> (21-i*3)) & 0x7]
    return p

# elegant implementation from Jamie, http://numericalrecipes.blogspot.com/2009/03/modular-multiplicative-inverse.html
#---
def extEuclideanAlg(a, b) :
    if b == 0 :
        return 1,0,a
    else :
        x, y, gcd = extEuclideanAlg(b, a % b)
    return y, x - y * (a // b),gcd

def modInvEuclid(a,m) :
    x,y,gcd = extEuclideanAlg(a,m)
    if gcd == 1 :
        return x % m
    else :
        return None
#---

def rsaDecrypt(inB):
    c = struct.unpack("<Q", inB)[0]

    p = 2795287379
    q = 3544934711
    n = p*q
    e = 41
    phi = (p-1)*(q-1)
    d = modInvEuclid(e, phi)
    #c = pow(u, e) % n

    dp = d % (p-1)
    dq = d % (q-1)
    qinv = modInvEuclid(q, p)

    m1 = modular_pow(c, dp, p)
    m2 = modular_pow(c, dq, q)
    if m1 < m2:
        h = (qinv * (m1-m2 + p)) % p
    else:
        h = (qinv * (m1-m2)) % p
    m = (m2 + h*q)
    return struct.pack("<Q", m)

def modular_pow(base, exponent, modulus):
    result = 1
    while exponent > 0:
        if (exponent & 1) == 1:
           result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def getMasterPwd(hashCode):
    a = decodeHash(hashCode)
    d = rsaDecrypt(a)
    return encodePassword(d)

def sony4x4Solver(in_str):
    in_str = in_str.replace("-", "").replace(" ", "").upper()
    return getMasterPwd(in_str)

def solvers():
    return [
        Solver('Sony',
               'Sony 4x4 digits [9DPK7V2F3RT6HX8J]',
               ['73KR-3FP9-PVKH-K29R'],
               r'^\s*[9DPK7V2F3RT6HX8J]{4}-[9DPK7V2F3RT6HX8J]{4}-[9DPK7V2F3RT6HX8J]{4}-[9DPK7V2F3RT6HX8J]{4}\s*$',
               sony4x4Solver),
    ]

def info():
    return '\n'.join([
        "Master Password Generator for Sony laptops (16 characters otp)",
        "Copyright (C) 2009-2010 dogbert <dogber1@gmail.com>",
        "",
        "After entering the wrong password for the third time, you will receive a",
        "hexadecimal code from which the password can be calculated,",
        "e.g. 73KR-3FP9-PVKH-K29R",
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
