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

from pygost.wrap import unwrap_cryptopro
from pygost.wrap import unwrap_gost
from pygost.wrap import wrap_cryptopro
from pygost.wrap import wrap_gost


class WrapGostTest(TestCase):
    def test_symmetric(self):
        for _ in range(1 << 8):
            kek = urandom(32)
            cek = urandom(32)
            ukm = urandom(8)
            wrapped = wrap_gost(ukm, kek, cek)
            unwrapped = unwrap_gost(kek, wrapped)
            self.assertEqual(unwrapped, cek)

    def test_invalid_length(self):
        with self.assertRaises(ValueError):
            unwrap_gost(urandom(32), urandom(41))
        with self.assertRaises(ValueError):
            unwrap_gost(urandom(32), urandom(45))


class WrapCryptoproTest(TestCase):
    def test_symmetric(self):
        for _ in range(1 << 8):
            kek = urandom(32)
            cek = urandom(32)
            ukm = urandom(8)
            wrapped = wrap_cryptopro(ukm, kek, cek)
            unwrapped = unwrap_cryptopro(kek, wrapped)
            self.assertEqual(unwrapped, cek)
