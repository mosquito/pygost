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

from os import urandom
from unittest import TestCase

from pygost.gost3410 import CURVE_PARAMS
from pygost.gost3410 import GOST3410Curve
from pygost.gost3410 import prv_unmarshal
from pygost.gost3410 import pub_unmarshal
from pygost.gost3410 import public_key
from pygost.gost3410_vko import kek_34102001
from pygost.gost3410_vko import kek_34102012256
from pygost.gost3410_vko import kek_34102012512
from pygost.gost3410_vko import ukm_unmarshal
from pygost.utils import bytes2long
from pygost.utils import hexdec


class TestVKO34102001(TestCase):
    def test_vector(self):
        curve = GOST3410Curve(*CURVE_PARAMS["GostR3410_2001_TestParamSet"])
        ukm = ukm_unmarshal(hexdec("5172be25f852a233"))
        prv1 = prv_unmarshal(hexdec("1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928"))
        prv2 = prv_unmarshal(hexdec("5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473"))
        kek = hexdec("ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6")
        pub1 = public_key(curve, prv1)
        pub2 = public_key(curve, prv2)
        self.assertEqual(kek_34102001(curve, prv1, pub2, ukm), kek)
        self.assertEqual(kek_34102001(curve, prv2, pub1, ukm), kek)

    def test_sequence(self):
        curve = GOST3410Curve(*CURVE_PARAMS["GostR3410_2001_TestParamSet"])
        for _ in range(10):
            ukm = ukm_unmarshal(urandom(8))
            prv1 = bytes2long(urandom(32))
            prv2 = bytes2long(urandom(32))
            pub1 = public_key(curve, prv1)
            pub2 = public_key(curve, prv2)
            kek1 = kek_34102001(curve, prv1, pub2, ukm)
            kek2 = kek_34102001(curve, prv2, pub1, ukm)
            self.assertEqual(kek1, kek2)
            kek1 = kek_34102001(curve, prv1, pub1, ukm)
            kek2 = kek_34102001(curve, prv2, pub2, ukm)
            self.assertNotEqual(kek1, kek2)


class TestVKO34102012256(TestCase):
    """RFC 7836
    """
    def test_vector(self):
        curve = GOST3410Curve(*CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"])
        ukm = ukm_unmarshal(hexdec("1d80603c8544c727"))
        prvA = prv_unmarshal(hexdec("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"))
        pubA = pub_unmarshal(hexdec("aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a"), mode=2012)
        prvB = prv_unmarshal(hexdec("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"))
        pubB = pub_unmarshal(hexdec("192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a65104883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79"), mode=2012)
        vko = hexdec("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")
        self.assertEqual(kek_34102012256(curve, prvA, pubB, ukm), vko)
        self.assertEqual(kek_34102012256(curve, prvB, pubA, ukm), vko)

    def test_sequence(self):
        curve = GOST3410Curve(*CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"])
        for _ in range(10):
            ukm = ukm_unmarshal(urandom(8))
            prv1 = bytes2long(urandom(32))
            prv2 = bytes2long(urandom(32))
            pub1 = public_key(curve, prv1)
            pub2 = public_key(curve, prv2)
            kek1 = kek_34102012256(curve, prv1, pub2, ukm)
            kek2 = kek_34102012256(curve, prv2, pub1, ukm)
            self.assertEqual(kek1, kek2)
            kek1 = kek_34102012256(curve, prv1, pub1, ukm)
            kek2 = kek_34102012256(curve, prv2, pub2, ukm)
            self.assertNotEqual(kek1, kek2)


class TestVKO34102012512(TestCase):
    """RFC 7836
    """
    def test_vector(self):
        curve = GOST3410Curve(*CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"])
        ukm = ukm_unmarshal(hexdec("1d80603c8544c727"))
        prvA = prv_unmarshal(hexdec("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"))
        pubA = pub_unmarshal(hexdec("aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a"), mode=2012)
        prvB = prv_unmarshal(hexdec("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"))
        pubB = pub_unmarshal(hexdec("192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a65104883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79"), mode=2012)
        vko = hexdec("79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf")
        self.assertEqual(kek_34102012512(curve, prvA, pubB, ukm), vko)
        self.assertEqual(kek_34102012512(curve, prvB, pubA, ukm), vko)

    def test_sequence(self):
        curve = GOST3410Curve(*CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"])
        for _ in range(10):
            ukm = ukm_unmarshal(urandom(8))
            prv1 = bytes2long(urandom(32))
            prv2 = bytes2long(urandom(32))
            pub1 = public_key(curve, prv1)
            pub2 = public_key(curve, prv2)
            kek1 = kek_34102012512(curve, prv1, pub2, ukm)
            kek2 = kek_34102012512(curve, prv2, pub1, ukm)
            self.assertEqual(kek1, kek2)
            kek1 = kek_34102012512(curve, prv1, pub1, ukm)
            kek2 = kek_34102012512(curve, prv2, pub2, ukm)
            self.assertNotEqual(kek1, kek2)
