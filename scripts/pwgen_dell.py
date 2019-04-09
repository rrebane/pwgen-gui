#!/usr/bin/env python

# Copyright 2019: Reimo Rebane <rebanerebane@gmail.com>
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
# Based on work by:
# * bacher09
#   https://github.com/bacher09/pwgen-for-bios/tree/master/src/keygen/dell
# * asyncritius — major contribution to dell generator
# * hpgl — dell generator
#   https://sites.google.com/site/hpglserv/Home/article

from scripts.solver import Solver, SolverError

import enum

class SuffixType(enum.Enum):
    ServiceTag = 1
    HDD = 2

class DellTag(enum.Enum):
    Tag595B = '595B'
    TagD35B = 'D35B'
    Tag2A7B = '2A7B'
    TagA95B = 'A95B'
    Tag1D3B = '1D3B'
    Tag6FF1 = '6FF1'
    Tag1F66 = '1F66'

SCAN_CODES = "\0\x1B1234567890-=\x08\x09qwertyuiop[]\x0D\xFFasdfghjkl;'`\xFF\\zxcvbnm,./"

ENC_SCANS = [
    0x05, 0x10, 0x13, 0x09, 0x32, 0x03, 0x25, 0x11, 0x1F, 0x17, 0x06, 0x15,
    0x30, 0x19, 0x26, 0x22, 0x0A, 0x02, 0x2C, 0x2F, 0x16, 0x14, 0x07, 0x18,
    0x24, 0x23, 0x31, 0x20, 0x1E, 0x08, 0x2D, 0x21, 0x04, 0x0B, 0x12, 0x2E
]

EXTRA_CHARS = {
    DellTag.Tag2A7B: '012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0',
    DellTag.Tag1D3B: '0BfIUG1kuPvc8A9Nl5DLZYSno7Ka6HMgqsJWm65yCQR94b21OTp7VFX2z0jihE33d4xtrew0',
    DellTag.Tag1F66: '0ewr3d4xtUG1ku0BfIp7VFb21OTSno7KDLZYqsJWa6HMgCQR94m65y9Nl5Pvc8AjihE3X2z0',
    DellTag.Tag6FF1: '08rptBxfbGVMz38IiSoeb360MKcLf4QtBCbWVzmH5wmZUcRR5DZG2xNCEv1nFtzsZB2bw1X0',
}

MD5MAGIC = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

MD5MAGIC2 = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039
]

ROTATION_TABLE = [
    [7, 12, 17, 22],
    [5, 9,  14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21]
]

INITIAL_DATA = [
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476
]

def encode(encType, encBlock):
    encoder = encType(encBlock)
    encoder.makeEncode()
    return encoder.result()

def bitwiseNot32(n, bits=32):
    return (1 << bits) - 1 - n

def add32(a, b):
    return (a + b) & 0xffffffff

def rotate(x, bitsrot):
    return (x >> (32 - bitsrot) | x << bitsrot) & 0xffffffff

def encF2(num1, num2, num3):
    return (((num3 ^ num2) & num1) ^ num3) & 0xffffffff

def encF3(num1, num2, num3):
    return (((num1 ^ num2) & num3) ^ num2) & 0xffffffff

def encF4(num1, num2, num3):
    return ((num2 ^ num1) ^ num3) & 0xffffffff

def encF5(num1, num2, num3):
    return ((num1 | bitwiseNot32(num3)) ^ num2) & 0xffffffff

def encF1(num1, num2):
    return (num1 + num2) & 0xffffffff

# Negative functions
def encF1N(num1, num2):
    return (num1 - num2) & 0xffffffff

def encF2N(num1, num2, num3):
    return encF2(num1, num2, bitwiseNot32(num3))

def encF4N(num1, num2, num3):
    return encF4(num1, bitwiseNot32(num2), num3)

def encF5N(num1, num2, num3):
    return encF5(bitwiseNot32(num1), num2, num3)

class Tag595BEncoder:
    def __init__(self, encBlock):
        self.encBlock = list(encBlock)
        self.encData = list(INITIAL_DATA)
        self.A = self.encData[0]
        self.B = self.encData[1]
        self.C = self.encData[2]
        self.D = self.encData[3]
        self.f1 = encF1N
        self.f2 = encF2N
        self.f3 = encF3
        self.f4 = encF4N
        self.f5 = encF5N
        self.md5table = MD5MAGIC

    def calculate(self, func, key1, key2):
        temp = func(self.B, self.C, self.D)
        return add32(self.A,
                     self.f1(temp, add32(self.md5table[key2], self.encBlock[key1])))

    def incrementData(self):
        self.encData[0] = add32(self.encData[0], self.A)
        self.encData[1] = add32(self.encData[1], self.B)
        self.encData[2] = add32(self.encData[2], self.C)
        self.encData[3] = add32(self.encData[3], self.D)

    def makeEncode(self):
        t = 0

        for i in range(64):
            if (i >> 4) == 0:
                t = self.calculate(self.f2, i & 15, i) # Use half byte
            elif (i >> 4) == 1:
                t = self.calculate(self.f3, (i * 5 + 1) & 15, i)
            elif (i >> 4) == 2:
                t = self.calculate(self.f4, (i * 3 + 5) & 15, i)
            elif (i >> 4) == 3:
                t = self.calculate(self.f5, (i * 7) & 15, i)
            self.A = self.D
            self.D = self.C
            self.C = self.B
            self.B = add32(rotate(t, ROTATION_TABLE[i >> 4][i & 3]), self.B)

        self.incrementData()

    def result(self):
        return list(self.encData)

class TagD35BEncoder(Tag595BEncoder):
    def __init__(self, encBlock):
        super().__init__(encBlock)
        self.f1 = encF1
        self.f2 = encF2
        self.f3 = encF3
        self.f4 = encF4
        self.f5 = encF5

class Tag1D3BEncoder(Tag595BEncoder):
    def __init__(self, encBlock):
        super().__init__(encBlock)
        self.f1 = encF1N
        self.f2 = encF2N
        self.f3 = encF3
        self.f4 = encF4N
        self.f5 = encF5N

    def makeEncode(self):
        for j in range(21):
            self.A = self.A | 0x97
            self.B = self.B ^ 0x8
            self.C = self.C | (0x60606161 - j)
            self.D = self.D ^ (0x50501010 + j)
            super().makeEncode()

class Tag1F66Encoder(Tag595BEncoder):
    def __init__(self, encBlock):
        super().__init__(encBlock)
        self.f1 = encF1N
        self.f2 = encF2N
        self.f3 = encF3
        self.f4 = encF4N
        self.f5 = encF5N
        self.md5table = MD5MAGIC2

    def makeEncode(self):
        t = 0

        for j in range(17):
            self.A = self.A | 0x100097
            self.B = self.B ^ 0xA0008
            self.C = self.C | (0x60606161 - j)
            self.D = self.D ^ (0x50501010 + j)

            for i in range(64):
                if (i >> 4) == 0:
                    t = self.calculate(self.f2, i & 15, i + 16)
                elif (i >> 4) == 1:
                    t = self.calculate(self.f3, (i * 5 + 1) & 15, i + 32)
                elif (i >> 4) == 2:
                    t = self.calculate(self.f4, (i * 3 + 5) & 15, i - 2 * (i & 12) + 12)
                elif (i >> 4) == 3:
                    t = self.calculate(self.f5, (i * 7) & 15, 2 * (i & 3) - (i & 15) + 12)
                self.A = self.D
                self.D = self.C
                self.C = self.B
                self.B = add32(rotate(t, ROTATION_TABLE[i >> 4][i & 3]), self.B)

            self.incrementData()

        for j in range(21):
            self.A = self.A | 0x97
            self.B = self.B ^ 0x8
            self.C = self.C | (0x50501010 - j)
            self.D = self.D ^ (0x60606161 + j)

            for i in range(64):
                if (i >> 4) == 0:
                    t = self.calculate(self.f4, (i * 3 + 5) & 15, 2 * (i & 3) - i + 44)
                elif (i >> 4) == 1:
                    t = self.calculate(self.f5, (i * 7) & 15, 2 * (i & 3) - i + 76)
                elif (i >> 4) == 2:
                    t = self.calculate(self.f2, i & 15, i & 15)
                elif (i >> 4) == 3:
                    t = self.calculate(self.f3, (i * 5 + 1) & 15, i - 32)
                self.A = self.D
                self.D = self.C
                self.C = self.B
                self.B = add32(rotate(t, ROTATION_TABLE[((i >> 4) + 2) & 3][i & 3]), self.B)

            self.incrementData()

class Tag6FF1Encoder(Tag595BEncoder):
    def __init__(self, encBlock):
        super().__init__(encBlock)
        self.f1 = encF1N
        self.f2 = encF2N
        self.f3 = encF3
        self.f4 = encF4N
        self.f5 = encF5N
        self.md5table = MD5MAGIC2

    def makeEncode(self):
        t = 0

        for j in range(23):
            self.A = self.A | 0xA08097
            self.B = self.B ^ 0xA010908
            self.C = self.C | (0x60606161 - j)
            self.D = self.D ^ (0x50501010 + j)

            for i in range(64):
                k = (i & 15) - ((i & 12) << 1) + 12
                if (i >> 4) == 0:
                    t = self.calculate(self.f2, i & 15, i + 32)
                elif (i >> 4) == 1:
                    t = self.calculate(self.f3, (i * 5 + 1) & 15, i & 15)
                elif (i >> 4) == 2:
                    t = self.calculate(self.f4, (i * 3 + 5) & 15, k + 16)
                elif (i >> 4) == 3:
                    t = self.calculate(self.f5, (i * 7) & 15, k + 48)
                self.A = self.D
                self.D = self.C
                self.C = self.B
                self.B = add32(rotate(t, ROTATION_TABLE[i >> 4][i & 3]), self.B)

            self.incrementData()

        for j in range(17):
            self.A = self.A | 0x100097
            self.B = self.B ^ 0xA0008
            self.C = self.C | (0x50501010 - j)
            self.D = self.D ^ (0x60606161 + j)

            for i in range(64):
                k = (i & 15) - ((i & 12) << 1) + 12
                if (i >> 4) == 0:
                    t = self.calculate(self.f4, ((i & 15) * 3 + 5) & 15, k + 16)
                elif (i >> 4) == 1:
                    t = self.calculate(self.f5, ((i & 3) * 7 + (i & 12) + 4) & 15, (i & 15) + 32)
                elif (i >> 4) == 2:
                    t = self.calculate(self.f2, k & 15, k)
                elif (i >> 4) == 3:
                    t = self.calculate(self.f3, ((i & 15) * 5 + 1) & 15, (i & 15) + 48)
                self.A = self.D
                self.D = self.C
                self.C = self.B
                self.B = add32(rotate(t, ROTATION_TABLE[((i >> 4) + 2) & 3][i & 3]), self.B)

            self.incrementData()

ENCODERS = {
    DellTag.Tag595B: Tag595BEncoder,
    DellTag.Tag2A7B: Tag595BEncoder, # same as 595B
    DellTag.TagA95B: Tag595BEncoder, # same as 595B
    DellTag.Tag1D3B: Tag1D3BEncoder,
    DellTag.TagD35B: TagD35BEncoder,
    DellTag.Tag1F66: Tag1F66Encoder,
    DellTag.Tag6FF1: Tag6FF1Encoder
}

def blockEncode(encBlock, tag):
    return encode(ENCODERS[tag], encBlock)

def dellTag(tag):
    try:
        return DellTag(tag)
    except ValueError as e:
        raise SolverError('Invalid tag in input: {}'.format(e)) from e

def dellKeygenHddOld(serial):
    serialArr = [ord(c) & 0xff for c in serial]
    ret = [0, 0, 0, 0, 0]
    ret.append((serialArr[1] >> 1 ) & 0xff)
    ret.append(((serialArr[1] >> 6) | (serialArr[0] << 2)) & 0xff)
    ret.append((serialArr[0] >> 3) & 0xff)

    for i in range(8):
        r = 0xAA
        if (ret[i] & 8) != 0:
            r = r ^ serialArr[1]
        if (ret[i] & 16) != 0:
            r = r ^ serialArr[0]
        ret[i] = ENC_SCANS[r % len(ENC_SCANS)]

    return ''.join([SCAN_CODES[c] for c in ret])

def calculateSuffix(serial, tag, type):
    suffix = [0 for x in range(8)]
    arr1 = [1, 2, 3, 4] if type == SuffixType.ServiceTag else [1, 10, 9, 8]
    arr2 = [4, 3, 2] if type == SuffixType.ServiceTag else [8, 9, 10]

    suffix[0] = serial[arr1[3]]
    suffix[1] = (serial[arr1[3]] >> 5) | (((serial[arr1[2]] >> 5) | (serial[arr1[2]] << 3)) & 0xF1)
    suffix[2] = serial[arr1[2]] >> 2
    suffix[3] = (serial[arr1[2]] >> 7) | (serial[arr1[1]] << 1)
    suffix[4] = (serial[arr1[1]] >> 4) | (serial[arr1[0]] << 4)
    suffix[5] = serial[1] >> 1
    suffix[6] = (serial[1] >> 6) | (serial[0] << 2)
    suffix[7] = serial[0] >> 3

    # normalize bytes
    suffix = [v & 0xff for v in suffix]

    codes_table = ENC_SCANS
    if tag in EXTRA_CHARS:
        codes_table = [ord(s) for s in EXTRA_CHARS[tag]]

    for i in range(8):
        r = 0xAA
        if suffix[i] & 1:
            r = r ^ serial[arr2[0]]
        if suffix[i] & 2:
            r = r ^ serial[arr2[1]]
        if (suffix[i] & 4):
            r = r ^ serial[arr2[2]]
        if (suffix[i] & 8):
            r = r ^ serial[1]
        if (suffix[i] & 16):
            r = r ^ serial[0]

        suffix[i] = codes_table[r % len(codes_table)]

    return suffix

def resultToString(arr, tag):
    r = arr[0] % 9
    result = ""
    for i in range(16):
        if tag in EXTRA_CHARS:
            table = EXTRA_CHARS[tag]
            result += table[arr[i] % len(table)]
        elif r <= i and len(result) < 8: # 595B, D35B, A95B
            result += SCAN_CODES[ENC_SCANS[arr[i] % len(ENC_SCANS)]]
    return result

def byteArrayToInt(arr):
    # convert byte array to 32-bit little-endian int array
    if len(arr) % 4 != 0:
        raise SolverError('Invalid array size')

    result = [0 for _ in range(len(arr) // 4)]
    for i in range(len(result)):
        result[i] = arr[i * 4] | (arr[i * 4 + 1] << 8) | (arr[i * 4 + 2] << 16) | (arr[i * 4 + 3] << 24)

    return result

def intArrayToByte(arr):
    # convert 32-bit little-endian array to byte array
    result = []
    for num in arr:
        result.append(num & 0xFF)
        result.append((num >> 8) & 0xFF)
        result.append((num >> 16) & 0xFF)
        result.append((num >> 24) & 0xFF)

    return result

def dellKeygen(serial, tag, type):
    fullSerial = ''
    if tag == DellTag.TagA95B:
        if type == SuffixType.ServiceTag:
            fullSerial = serial + DellTag.Tag595B.value
        else: # HDD
            fullSerial = serial[3:] + '\0\0\0' + DellTag.Tag595B.value
    else:
        fullSerial = serial + tag.value

    fullSerialArray = [ord(c) & 0xff for c in fullSerial]

    fullSerialArray.extend(calculateSuffix(fullSerialArray, tag, type))
    cnt = 23
    for _ in range(len(fullSerialArray), cnt + 1):
        fullSerialArray.append(0)
    fullSerialArray[cnt] = 0x80
    encBlock = byteArrayToInt(fullSerialArray)
    for _ in range(len(encBlock), 16):
        encBlock.append(0)
    encBlock[14] = cnt << 3
    decodedBytes = intArrayToByte(blockEncode(encBlock, tag))

    return resultToString(decodedBytes, tag)

def dellHddOldSolver(in_str):
    in_str = in_str.strip().replace('-', '')
    return dellKeygenHddOld(in_str)

def dellSolver(in_str):
    in_str = in_str.strip().replace('-', '')
    return dellKeygen(in_str[0:7], dellTag(in_str[7:11].upper()), SuffixType.ServiceTag)

def dellHddSolver(in_str):
    in_str = in_str.strip().replace('-', '')
    return dellKeygen(in_str[0:11], dellTag(in_str[11:15].upper()), SuffixType.HDD)

def solvers():
    return [
        Solver('Dell',
               'Dell from HDD serial number (old)',
               ['12345678901'],
               r'^\s*\w{11}\s*$',
               dellHddOldSolver),
        Solver('Dell',
               'Dell from serial number',
               ['1234567-595B'],
               r'^\s*\w{7}-\w{4}\s*$',
               dellSolver),
        Solver('Dell',
               'Dell from HDD serial number (new)',
               ['1234567890A-595B'],
               r'^\s*\w{11}-\w{4}\s*$',
               dellHddSolver),
    ]

def info():
    return '\n'.join([
        'Master Password Generator for Dell laptops',
        'Copyright (C) 2019 Reimo Rebane <rebanerebane@gmail.com>',
        '',
        'Original program by 2007-2010 hpgl',
        'This port is based on code by bacher09: https://github.com/bacher09/pwgen-for-bios/tree/master/src/keygen/dell',
        '',
        'Short service tag should be right padded with \'*\' up to length 7 chars.',
        'HDD serial number is right 11 chars from real HDDSerNum left padded with \'*\'.',
        'Some BIOSes have left padded HDD serial number with spaces instead \'*\'.',
    ])

def run(in_str = None):
    if in_str is None:
        print(info())
        in_str = input('Please enter the serial number: ')

    found_solver = False
    for solver in solvers():
        if solver.is_valid_input(in_str):
            password = solver.solve(in_str)
            print('{}: {}'.format(solver.description, password))

    if not found_solver:
        print("No solver for given input")

if __name__ == '__main__':
    run()
