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
""" GOST R 34.13-2015: Modes of operation for block ciphers

This module currently includes only padding methods.
"""


def pad_size(data_size, blocksize):
    """Calculate required pad size to full up BLOCKSIZE
    """
    if data_size < blocksize:
        return blocksize - data_size
    if data_size % blocksize == 0:
        return 0
    return blocksize - data_size % blocksize


def pad1(data, blocksize):
    """Padding method 1

    Just fill up with zeros if necessary.
    """
    return data + b'\x00' * pad_size(len(data), blocksize)


def pad2(data, blocksize):
    """Padding method 2 (also known as ISO/IEC 7816-4)

    Add one bit and then fill up with zeros.
    """
    return data + b'\x80' + b'\x00' * pad_size(len(data) + 1, blocksize)


def pad3(data, blocksize):
    """Padding method 3
    """
    if pad_size(len(data), blocksize) == 0:
        return data
    return pad2(data, blocksize)
