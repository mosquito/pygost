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

from os import urandom
from unittest import TestCase

from pygost.x509 import keypair_gen
from pygost.x509 import sign
from pygost.x509 import sign_digest
from pygost.x509 import verify
from pygost.x509 import verify_digest
from pygost.x509 import SIZE_3410_2001
from pygost.x509 import SIZE_3410_2012


class X5092001Test(TestCase):
    def test_symmetric(self):
        for _ in range(1 << 4):
            prv, pub = keypair_gen(urandom(SIZE_3410_2001), mode=2001)
            digest = urandom(SIZE_3410_2001)
            self.assertTrue(verify_digest(
                pub, digest, sign_digest(prv, digest, mode=2001), mode=2001
            ))
            data = digest
            self.assertTrue(verify(
                pub, data, sign(prv, data, mode=2001), mode=2001
            ))


class X5092012Test(TestCase):
    def test_symmetric(self):
        for _ in range(1 << 4):
            prv, pub = keypair_gen(urandom(SIZE_3410_2012), mode=2012)
            digest = urandom(SIZE_3410_2012)
            self.assertTrue(verify_digest(
                pub, digest, sign_digest(prv, digest, mode=2012), mode=2012,
            ))
            data = digest
            self.assertTrue(verify(
                pub, data, sign(prv, data, mode=2012), mode=2012,
            ))
