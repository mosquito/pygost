# coding: utf-8
# PyGOST -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2017 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""GOST 34.12-2015 64 and 128 bit block ciphers (:rfc:`7801`)

Several precalculations are performed during this module importing.
"""

from pygost.gost28147 import block2ns as gost28147_block2ns
from pygost.gost28147 import decrypt as gost28147_decrypt
from pygost.gost28147 import encrypt as gost28147_encrypt
from pygost.gost28147 import ns2block as gost28147_ns2block
from pygost.utils import strxor
from pygost.utils import xrange  # pylint: disable=redefined-builtin


LC = bytearray((
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
))
PI = bytearray((
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5,
    132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235,
    52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181,
    112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161,
    150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117,
    25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245,
    36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15,
    236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151,
    96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70,
    146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64,
    134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73,
    76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164,
    45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230,
    244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
))

########################################################################
# Precalculate inverted PI value as a performance optimization.
# Actually it can be computed only once and saved on the disk.
########################################################################
PIinv = bytearray(256)
for x in xrange(256):
    PIinv[PI[x]] = x


def gf(a, b):
    c = 0
    while b:
        if b & 1:
            c ^= a
        if a & 0x80:
            a = (a << 1) ^ 0x1C3
        else:
            a <<= 1
        b >>= 1
    return c

########################################################################
# Precalculate all possible gf(byte, byte) values as a performance
# optimization.
# Actually it can be computed only once and saved on the disk.
########################################################################


GF = [bytearray(256) for _ in xrange(256)]

for x in xrange(256):
    for y in xrange(256):
        GF[x][y] = gf(x, y)


def L(blk, rounds=16):
    for _ in range(rounds):
        t = blk[15]
        for i in range(14, -1, -1):
            blk[i + 1] = blk[i]
            t ^= GF[blk[i]][LC[i]]
        blk[0] = t
    return blk


def Linv(blk):
    for _ in range(16):
        t = blk[0]
        for i in range(15):
            blk[i] = blk[i + 1]
            t ^= GF[blk[i]][LC[i]]
        blk[15] = t
    return blk

########################################################################
# Precalculate values of the C -- it does not depend on key.
# Actually it can be computed only once and saved on the disk.
########################################################################


C = []

for x in range(1, 33):
    y = bytearray(16)
    y[15] = x
    C.append(L(y))


def lp(blk):
    return L([PI[v] for v in blk])


class GOST3412Kuznechik(object):
    """GOST 34.12-2015 128-bit block cipher Кузнечик (Kuznechik)
    """
    def __init__(self, key):
        """
        :param key: encryption/decryption key
        :type key: bytes, 32 bytes

        Key scheduling (roundkeys precomputation) is performed here.
        """
        kr0 = bytearray(key[:16])
        kr1 = bytearray(key[16:])
        self.ks = [kr0, kr1]
        for i in range(4):
            for j in range(8):
                k = lp(bytearray(strxor(C[8 * i + j], kr0)))
                kr0, kr1 = [strxor(k, kr1), kr0]
            self.ks.append(kr0)
            self.ks.append(kr1)

    def encrypt(self, blk):
        blk = bytearray(blk)
        for i in range(9):
            blk = lp(bytearray(strxor(self.ks[i], blk)))
        return bytes(strxor(self.ks[9], blk))

    def decrypt(self, blk):
        blk = bytearray(blk)
        for i in range(9, 0, -1):
            blk = [PIinv[v] for v in Linv(bytearray(strxor(self.ks[i], blk)))]
        return bytes(strxor(self.ks[0], blk))


class GOST3412Magma(object):
    """GOST 34.12-2015 64-bit block cipher Магма (Magma)
    """
    def __init__(self, key):
        """
        :param key: encryption/decryption key
        :type key: bytes, 32 bytes
        """
        # Backward compatibility key preparation for 28147-89 key schedule
        self.key = b"".join(key[i * 4:i * 4 + 4][::-1] for i in range(8))
        self.sbox = "Gost28147_tc26_ParamZ"

    def encrypt(self, blk):
        return gost28147_ns2block(gost28147_encrypt(
            self.sbox,
            self.key,
            gost28147_block2ns(blk[::-1]),
        ))[::-1]

    def decrypt(self, blk):
        return gost28147_ns2block(gost28147_decrypt(
            self.sbox,
            self.key,
            gost28147_block2ns(blk[::-1]),
        ))[::-1]
