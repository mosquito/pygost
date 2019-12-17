# coding: utf-8
# PyGOST -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2020 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
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

from pygost import gost34112012256
from pygost import gost34112012512
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.gost34112012512 import pbkdf2
from pygost.utils import hexdec
from pygost.utils import hexenc


class TestCopy(TestCase):
    def runTest(self):
        m = GOST34112012256()
        c = m.copy()
        m.update(b"foobar")
        c.update(b"foo")
        c.update(b"bar")
        self.assertSequenceEqual(m.digest(), c.digest())


class TestHMAC(TestCase):
    """RFC 7836
    """
    def test_256(self):
        for digestmod in (GOST34112012256, gost34112012256):
            self.assertSequenceEqual(
                hmac.new(
                    key=hexdec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                    msg=hexdec("0126bdb87800af214341456563780100"),
                    digestmod=digestmod,
                ).hexdigest(),
                "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9",
            )

    def test_512(self):
        for digestmod in (GOST34112012512, gost34112012512):
            self.assertSequenceEqual(
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
        self.assertSequenceEqual(
            GOST34112012512(m).digest(),
            hexdec("486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b")[::-1]
        )
        self.assertSequenceEqual(
            GOST34112012256(m).digest(),
            hexdec("00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")[::-1]
        )

    def test_m2(self):
        m = u"Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы".encode("cp1251")
        self.assertSequenceEqual(m, hexdec("fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1")[::-1])
        self.assertSequenceEqual(
            GOST34112012512(m).digest(),
            hexdec("28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e")[::-1]
        )
        self.assertSequenceEqual(
            GOST34112012256(m).digest(),
            hexdec("508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d")[::-1]
        )

    def test_habr144(self):
        """Test vector from https://habr.com/ru/post/450024/
        """
        m = hexdec("d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100000000000000001000002400000001000000feffffff0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        self.assertSequenceEqual(
            GOST34112012256(m).hexdigest(),
            "c766085540caaa8953bfcf7a1ba220619cee50d65dc242f82f23ba4b180b18e0",
        )


class TestPBKDF2(TestCase):
    """http://tc26.ru/.../R_50.1.111-2016.pdf
    """
    def test_1(self):
        self.assertSequenceEqual(
            hexenc(pbkdf2(b"password", b"salt", 1, 64)),
            "64770af7f748c3b1c9ac831dbcfd85c26111b30a8a657ddc3056b80ca73e040d2854fd36811f6d825cc4ab66ec0a68a490a9e5cf5156b3a2b7eecddbf9a16b47",
        )

    def test_2(self):
        self.assertSequenceEqual(
            hexenc(pbkdf2(b"password", b"salt", 2, 64)),
            "5a585bafdfbb6e8830d6d68aa3b43ac00d2e4aebce01c9b31c2caed56f0236d4d34b2b8fbd2c4e89d54d46f50e47d45bbac301571743119e8d3c42ba66d348de",
        )

    def test_3(self):
        self.assertSequenceEqual(
            hexenc(pbkdf2(b"password", b"salt", 4096, 64)),
            "e52deb9a2d2aaff4e2ac9d47a41f34c20376591c67807f0477e32549dc341bc7867c09841b6d58e29d0347c996301d55df0d34e47cf68f4e3c2cdaf1d9ab86c3",
        )

    @skip("it takes too long")
    def test_4(self):
        self.assertSequenceEqual(
            hexenc(pbkdf2(b"password", b"salt", 1677216, 64)),
            "49e4843bba76e300afe24c4d23dc7392def12f2c0e244172367cd70a8982ac361adb601c7e2a314e8cb7b1e9df840e36ab5615be5d742b6cf203fb55fdc48071",
        )

    def test_5(self):
        self.assertSequenceEqual(
            hexenc(pbkdf2(
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                100,
            )),
            "b2d8f1245fc4d29274802057e4b54e0a0753aa22fc53760b301cf008679e58fe4bee9addcae99ba2b0b20f431a9c5e50f395c89387d0945aedeca6eb4015dfc2bd2421ee9bb71183ba882ceebfef259f33f9e27dc6178cb89dc37428cf9cc52a2baa2d3a",
        )

    def test_6(self):
        self.assertSequenceEqual(
            hexenc(pbkdf2(b"pass\x00word", b"sa\x00lt", 4096, 64)),
            "50df062885b69801a3c10248eb0a27ab6e522ffeb20c991c660f001475d73a4e167f782c18e97e92976d9c1d970831ea78ccb879f67068cdac1910740844e830",
        )
