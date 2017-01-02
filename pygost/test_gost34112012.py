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
import hmac

from pygost import gost34112012256
from pygost import gost34112012512
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.utils import hexdec


class TestCopy(TestCase):
    def runTest(self):
        m = GOST34112012256()
        c = m.copy()
        m.update(b"foobar")
        c.update(b"foo")
        c.update(b"bar")
        self.assertEqual(m.digest(), c.digest())


class TestHMAC(TestCase):
    """RFC 7836
    """
    def test_256(self):
        for digestmod in (GOST34112012256, gost34112012256):
            self.assertEqual(
                hmac.new(
                    key=hexdec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                    msg=hexdec("0126bdb87800af214341456563780100"),
                    digestmod=digestmod,
                ).hexdigest(),
                "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9",
            )

    def test_512(self):
        for digestmod in (GOST34112012512, gost34112012512):
            self.assertEqual(
                hmac.new(
                    key=hexdec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                    msg=hexdec("0126bdb87800af214341456563780100"),
                    digestmod=digestmod,
                ).hexdigest(),
                "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6",
            )


class TestVectors(TestCase):
    def test_m1(self):
        m = hexdec("323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130")[::-1]
        self.assertEqual(
            GOST34112012512(m).digest(),
            hexdec("486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b")[::-1]
        )
        self.assertEqual(
            GOST34112012256(m).digest(),
            hexdec("00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")[::-1]
        )

    def test_m2(self):
        m = hexdec("fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1")[::-1]
        self.assertEqual(
            GOST34112012512(m).digest(),
            hexdec("28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e")[::-1]
        )
        self.assertEqual(
            GOST34112012256(m).digest(),
            hexdec("508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d")[::-1]
        )
