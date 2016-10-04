# coding: utf-8
# PyGOST -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2016 Sergey Matveev <stargrave@stargrave.org>
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
import hmac

from pygost import gost3411_94
from pygost.gost3411_94 import GOST341194


class TestCopy(TestCase):
    def runTest(self):
        m = GOST341194()
        c = m.copy()
        m.update(b'foobar')
        c.update(b'foo')
        c.update(b'bar')
        self.assertEqual(m.digest(), c.digest())


class TestHMACPEP247(TestCase):
    def runTest(self):
        h = hmac.new(b'foo', digestmod=gost3411_94)
        h.update(b'foobar')
        h.digest()


class TestVectors(TestCase):
    def test_empty(self):
        self.assertEqual(
            GOST341194(b'', "GostR3411_94_TestParamSet").hexdigest(),
            "8d0f49492c91f45a68ff5c05d2c2b4ab78027b9aab5ce3feff5267c49cb985ce",
        )

    def test_a(self):
        self.assertEqual(
            GOST341194(b'a', "GostR3411_94_TestParamSet").hexdigest(),
            "dd14f362cefd49f873a5c644431b87219c3449661f808ac8e9667c369e532cd4",
        )

    def test_abc(self):
        self.assertEqual(
            GOST341194(b'abc', "GostR3411_94_TestParamSet").hexdigest(),
            "1dd5a4067c49703b75bc75c9290f5ecbb5eb85229e7277a2b2b14fc4484313f3",
        )

    def test_message_digest(self):
        self.assertEqual(
            GOST341194(b'message digest', "GostR3411_94_TestParamSet").hexdigest(),
            "4d9a88a416de2fdb72de483f27652b5869243dec59be0cb6992c8fb1ec3444ad",
        )

    def test_Us(self):
        self.assertEqual(
            GOST341194(128 * b'U', "GostR3411_94_TestParamSet").hexdigest(),
            "a43357fee8a926d9522a06870a66251c553e2774a0851d0cef0c1825eda3a353",
        )

    def test_dog(self):
        self.assertEqual(
            GOST341194(
                b'The quick brown fox jumps over the lazy dog',
                "GostR3411_94_TestParamSet",
            ).hexdigest(),
            "94421f6d370fa1d16ba7ac5e31296529c968047dca9bf4258ac59a0c41fab777",
        )

    def test_cog(self):
        self.assertEqual(
            GOST341194(
                b'The quick brown fox jumps over the lazy cog',
                "GostR3411_94_TestParamSet",
            ).hexdigest(),
            "45c4ee4ee1d25091312135540d6702e6677f7a73b5da31e10b8bb7aadac4eba3",
        )

    def test_rfc32(self):
        self.assertEqual(
            GOST341194(
                b'This is message, length=32 bytes',
                "GostR3411_94_TestParamSet",
            ).hexdigest(),
            "faff37a615a816691cff3ef8b68ca247e09525f39f8119832eb81975d366c4b1",
        )

    def test_rfc50(self):
        self.assertEqual(
            GOST341194(
                b'Suppose the original message has length = 50 bytes',
                "GostR3411_94_TestParamSet",
            ).hexdigest(),
            "0852f5623b89dd57aeb4781fe54df14eeafbc1350613763a0d770aa657ba1a47",
        )


class TestVectorsCryptoPro(TestCase):
    """ CryptoPro S-box test vectors
    """
    def test_empty(self):
        self.assertEqual(
            GOST341194(b'', "GostR3411_94_CryptoProParamSet").hexdigest(),
            "c056d64c2383c44a58139c9b560111ac133e43fb840f838714840ca33c5f1e98",
        )

    def test_a(self):
        self.assertEqual(
            GOST341194(b'a', "GostR3411_94_CryptoProParamSet").hexdigest(),
            "1130402fcfaaf1ef3c13e3173f105a715580f7c97900af37bf832128dd524ce7",
        )

    def test_abc(self):
        self.assertEqual(
            GOST341194(b'abc', "GostR3411_94_CryptoProParamSet").hexdigest(),
            "2cd42ff986293b167e994381ed59747414dd24953677762d39d718bf6d0585b2",
        )

    def test_message_digest(self):
        self.assertEqual(
            GOST341194(
                b'message digest',
                "GostR3411_94_CryptoProParamSet",
            ).hexdigest(),
            "a01b72299bc39a540fd672a99a72b4bdfe74417386986efaeb01a42add4160bc",
        )

    def test_dog(self):
        self.assertEqual(
            GOST341194(
                b'The quick brown fox jumps over the lazy dog',
                "GostR3411_94_CryptoProParamSet",
            ).hexdigest(),
            "760a8365d570476e787254761be7656774021b1f3de56f588c501a364a290490",
        )

    def test_32(self):
        self.assertEqual(
            GOST341194(
                b'This is message, length=32 bytes',
                "GostR3411_94_CryptoProParamSet",
            ).hexdigest(),
            "eb48de3e89e71bcb695fc752d617fae757f34fa77fa58ee114c5bdb7f7c2ef2c",
        )

    def test_50(self):
        self.assertEqual(
            GOST341194(
                b'Suppose the original message has length = 50 bytes',
                "GostR3411_94_CryptoProParamSet",
            ).hexdigest(),
            "1150a63031dc611a5f5e40d93153f74ebde8216f6792c25a91cfcabc5c0c73c3",
        )

    def test_Us(self):
        self.assertEqual(
            GOST341194(128 * b'U', "GostR3411_94_CryptoProParamSet").hexdigest(),
            "e8c449f608104c512710cd37fded920df1e86b211623fa27f4bb914661c74a1c",
        )
