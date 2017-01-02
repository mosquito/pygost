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

from unittest import skip
from unittest import TestCase
import hmac

from pygost import gost341194
from pygost.gost341194 import GOST341194
from pygost.gost341194 import pbkdf2
from pygost.utils import hexenc


class TestCopy(TestCase):
    def runTest(self):
        m = GOST341194()
        c = m.copy()
        m.update(b"foobar")
        c.update(b"foo")
        c.update(b"bar")
        self.assertEqual(m.digest(), c.digest())


class TestHMACPEP247(TestCase):
    def runTest(self):
        h = hmac.new(b"foo", digestmod=gost341194)
        h.update(b"foobar")
        h.digest()


class TestVectors(TestCase):
    def test_empty(self):
        self.assertEqual(
            GOST341194(b"", "GostR3411_94_TestParamSet").hexdigest(),
            "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d",
        )

    def test_a(self):
        self.assertEqual(
            GOST341194(b"a", "GostR3411_94_TestParamSet").hexdigest(),
            "d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd",
        )

    def test_abc(self):
        self.assertEqual(
            GOST341194(b"abc", "GostR3411_94_TestParamSet").hexdigest(),
            "f3134348c44fb1b2a277729e2285ebb5cb5e0f29c975bc753b70497c06a4d51d",
        )

    def test_message_digest(self):
        self.assertEqual(
            GOST341194(b"message digest", "GostR3411_94_TestParamSet").hexdigest(),
            "ad4434ecb18f2c99b60cbe59ec3d2469582b65273f48de72db2fde16a4889a4d",
        )

    def test_Us(self):
        self.assertEqual(
            GOST341194(128 * b"U", "GostR3411_94_TestParamSet").hexdigest(),
            "53a3a3ed25180cef0c1d85a074273e551c25660a87062a52d926a9e8fe5733a4",
        )

    def test_dog(self):
        self.assertEqual(
            GOST341194(b"The quick brown fox jumps over the lazy dog", "GostR3411_94_TestParamSet",).hexdigest(),
            "77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294",
        )

    def test_cog(self):
        self.assertEqual(
            GOST341194(b"The quick brown fox jumps over the lazy cog", "GostR3411_94_TestParamSet",).hexdigest(),
            "a3ebc4daaab78b0be131dab5737a7f67e602670d543521319150d2e14eeec445",
        )

    def test_rfc32(self):
        self.assertEqual(
            GOST341194(b"This is message, length=32 bytes", "GostR3411_94_TestParamSet",).hexdigest(),
            "b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa",
        )

    def test_rfc50(self):
        self.assertEqual(
            GOST341194(b"Suppose the original message has length = 50 bytes", "GostR3411_94_TestParamSet",).hexdigest(),
            "471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208",
        )


class TestVectorsCryptoPro(TestCase):
    """ CryptoPro S-box test vectors
    """
    def test_empty(self):
        self.assertEqual(
            GOST341194(b"", "GostR3411_94_CryptoProParamSet").hexdigest(),
            "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
        )

    def test_a(self):
        self.assertEqual(
            GOST341194(b"a", "GostR3411_94_CryptoProParamSet").hexdigest(),
            "e74c52dd282183bf37af0079c9f78055715a103f17e3133ceff1aacf2f403011",
        )

    def test_abc(self):
        self.assertEqual(
            GOST341194(b"abc", "GostR3411_94_CryptoProParamSet").hexdigest(),
            "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c",
        )

    def test_message_digest(self):
        self.assertEqual(
            GOST341194(b"message digest", "GostR3411_94_CryptoProParamSet",).hexdigest(),
            "bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0",
        )

    def test_dog(self):
        self.assertEqual(
            GOST341194(b"The quick brown fox jumps over the lazy dog", "GostR3411_94_CryptoProParamSet",).hexdigest(),
            "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76",
        )

    def test_32(self):
        self.assertEqual(
            GOST341194(b"This is message, length=32 bytes", "GostR3411_94_CryptoProParamSet",).hexdigest(),
            "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb",
        )

    def test_50(self):
        self.assertEqual(
            GOST341194(b"Suppose the original message has length = 50 bytes", "GostR3411_94_CryptoProParamSet",).hexdigest(),
            "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011",
        )

    def test_Us(self):
        self.assertEqual(
            GOST341194(128 * b"U", "GostR3411_94_CryptoProParamSet").hexdigest(),
            "1c4ac7614691bbf427fa2316216be8f10d92edfd37cd1027514c1008f649c4e8",
        )


class TestPBKDF2(TestCase):
    """http://tc26.ru/methods/containers_v1/Addition_to_PKCS5_v1_0.pdf test vectors
    """
    def test_1(self):
        self.assertEqual(
            hexenc(pbkdf2(b"password", b"salt", 1, 32)),
            "7314e7c04fb2e662c543674253f68bd0b73445d07f241bed872882da21662d58",
        )

    def test_2(self):
        self.assertEqual(
            hexenc(pbkdf2(b"password", b"salt", 2, 32)),
            "990dfa2bd965639ba48b07b792775df79f2db34fef25f274378872fed7ed1bb3",
        )

    def test_3(self):
        self.assertEqual(
            hexenc(pbkdf2(b"password", b"salt", 4096, 32)),
            "1f1829a94bdff5be10d0aeb36af498e7a97467f3b31116a5a7c1afff9deadafe",
        )

    @skip("it takes too long")
    def test_4(self):
        self.assertEqual(
            hexenc(pbkdf2(b"password", b"salt", 16777216, 32)),
            "a57ae5a6088396d120850c5c09de0a525100938a59b1b5c3f7810910d05fcd97",
        )

    def test_5(self):
        self.assertEqual(
            hexenc(pbkdf2(
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                40,
            )),
            "788358c69cb2dbe251a7bb17d5f4241f265a792a35becde8d56f326b49c85047b7638acb4764b1fd",
        )

    def test_6(self):
        self.assertEqual(
            hexenc(pbkdf2(
                b"pass\x00word",
                b"sa\x00lt",
                4096,
                20,
            )),
            "43e06c5590b08c0225242373127edf9c8e9c3291",
        )
