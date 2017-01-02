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

from pygost.gost28147_mac import MAC


class TestMAC(TestCase):
    """ Test vectors generated with libgcl3 library
    """
    k = b"This is message\xFF length\x0032 bytes"

    def test_a(self):
        self.assertEqual(
            MAC(self.k, b"a").hexdigest(),
            "bd5d3b5b2b7b57af",
        )

    def test_abc(self):
        self.assertEqual(
            MAC(self.k, b"abc").hexdigest(),
            "28661e40805b1ff9",
        )

    def test_128U(self):
        self.assertEqual(
            MAC(self.k, 128 * b"U").hexdigest(),
            "1a06d1bad74580ef",
        )

    def test_13x(self):
        self.assertEqual(
            MAC(self.k, 13 * b"x").hexdigest(),
            "917ee1f1a668fbd3",
        )

    def test_parts(self):
        m = MAC(self.k)
        m.update(b"foo")
        m.update(b"bar")
        self.assertEqual(m.digest(), MAC(self.k, b"foobar").digest())

    def test_copy(self):
        m = MAC(self.k, b"foo")
        c = m.copy()
        m.update(b"barbaz")
        c.update(b"bar")
        c.update(b"baz")
        self.assertEqual(m.digest(), c.digest())
