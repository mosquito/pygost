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

from unittest import TestCase

from pygost.gost3412 import C
from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3412 import GOST3412Magma
from pygost.gost3412 import L
from pygost.gost3412 import PI
from pygost.utils import hexdec


def S(blk):
    return bytearray(PI[v] for v in blk)


def R(blk):
    return L(blk, rounds=1)


class STest(TestCase):
    def test_vec1(self):
        blk = bytearray(hexdec("ffeeddccbbaa99881122334455667700"))
        self.assertEqual(S(blk), hexdec("b66cd8887d38e8d77765aeea0c9a7efc"))

    def test_vec2(self):
        blk = bytearray(hexdec("b66cd8887d38e8d77765aeea0c9a7efc"))
        self.assertEqual(S(blk), hexdec("559d8dd7bd06cbfe7e7b262523280d39"))

    def test_vec3(self):
        blk = bytearray(hexdec("559d8dd7bd06cbfe7e7b262523280d39"))
        self.assertEqual(S(blk), hexdec("0c3322fed531e4630d80ef5c5a81c50b"))

    def test_vec4(self):
        blk = bytearray(hexdec("0c3322fed531e4630d80ef5c5a81c50b"))
        self.assertEqual(S(blk), hexdec("23ae65633f842d29c5df529c13f5acda"))


class RTest(TestCase):
    def test_vec1(self):
        blk = bytearray(hexdec("00000000000000000000000000000100"))
        self.assertEqual(R(blk), hexdec("94000000000000000000000000000001"))

    def test_vec2(self):
        blk = bytearray(hexdec("94000000000000000000000000000001"))
        self.assertEqual(R(blk), hexdec("a5940000000000000000000000000000"))

    def test_vec3(self):
        blk = bytearray(hexdec("a5940000000000000000000000000000"))
        self.assertEqual(R(blk), hexdec("64a59400000000000000000000000000"))

    def test_vec4(self):
        blk = bytearray(hexdec("64a59400000000000000000000000000"))
        self.assertEqual(R(blk), hexdec("0d64a594000000000000000000000000"))


class LTest(TestCase):
    def test_vec1(self):
        blk = bytearray(hexdec("64a59400000000000000000000000000"))
        self.assertEqual(L(blk), hexdec("d456584dd0e3e84cc3166e4b7fa2890d"))

    def test_vec2(self):
        blk = bytearray(hexdec("d456584dd0e3e84cc3166e4b7fa2890d"))
        self.assertEqual(L(blk), hexdec("79d26221b87b584cd42fbc4ffea5de9a"))

    def test_vec3(self):
        blk = bytearray(hexdec("79d26221b87b584cd42fbc4ffea5de9a"))
        self.assertEqual(L(blk), hexdec("0e93691a0cfc60408b7b68f66b513c13"))

    def test_vec4(self):
        blk = bytearray(hexdec("0e93691a0cfc60408b7b68f66b513c13"))
        self.assertEqual(L(blk), hexdec("e6a8094fee0aa204fd97bcb0b44b8580"))


class KuznechikTest(TestCase):
    key = hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    plaintext = hexdec("1122334455667700ffeeddccbbaa9988")
    ciphertext = hexdec("7f679d90bebc24305a468d42b9d4edcd")

    def test_c(self):
        self.assertEqual(C[0], hexdec("6ea276726c487ab85d27bd10dd849401"))
        self.assertEqual(C[1], hexdec("dc87ece4d890f4b3ba4eb92079cbeb02"))
        self.assertEqual(C[2], hexdec("b2259a96b4d88e0be7690430a44f7f03"))
        self.assertEqual(C[3], hexdec("7bcd1b0b73e32ba5b79cb140f2551504"))
        self.assertEqual(C[4], hexdec("156f6d791fab511deabb0c502fd18105"))
        self.assertEqual(C[5], hexdec("a74af7efab73df160dd208608b9efe06"))
        self.assertEqual(C[6], hexdec("c9e8819dc73ba5ae50f5b570561a6a07"))
        self.assertEqual(C[7], hexdec("f6593616e6055689adfba18027aa2a08"))

    def test_roundkeys(self):
        ciph = GOST3412Kuznechik(self.key)
        self.assertEqual(ciph.ks[0], hexdec("8899aabbccddeeff0011223344556677"))
        self.assertEqual(ciph.ks[1], hexdec("fedcba98765432100123456789abcdef"))
        self.assertEqual(ciph.ks[2], hexdec("db31485315694343228d6aef8cc78c44"))
        self.assertEqual(ciph.ks[3], hexdec("3d4553d8e9cfec6815ebadc40a9ffd04"))
        self.assertEqual(ciph.ks[4], hexdec("57646468c44a5e28d3e59246f429f1ac"))
        self.assertEqual(ciph.ks[5], hexdec("bd079435165c6432b532e82834da581b"))
        self.assertEqual(ciph.ks[6], hexdec("51e640757e8745de705727265a0098b1"))
        self.assertEqual(ciph.ks[7], hexdec("5a7925017b9fdd3ed72a91a22286f984"))
        self.assertEqual(ciph.ks[8], hexdec("bb44e25378c73123a5f32f73cdb6e517"))
        self.assertEqual(ciph.ks[9], hexdec("72e9dd7416bcf45b755dbaa88e4a4043"))

    def test_encrypt(self):
        ciph = GOST3412Kuznechik(self.key)
        self.assertEqual(ciph.encrypt(self.plaintext), self.ciphertext)

    def test_decrypt(self):
        ciph = GOST3412Kuznechik(self.key)
        self.assertEqual(ciph.decrypt(self.ciphertext), self.plaintext)


class MagmaTest(TestCase):
    key = hexdec("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = hexdec("fedcba9876543210")
    ciphertext = hexdec("4ee901e5c2d8ca3d")

    def test_encrypt(self):
        ciph = GOST3412Magma(self.key)
        self.assertEqual(ciph.encrypt(self.plaintext), self.ciphertext)

    def test_decrypt(self):
        ciph = GOST3412Magma(self.key)
        self.assertEqual(ciph.decrypt(self.ciphertext), self.plaintext)
