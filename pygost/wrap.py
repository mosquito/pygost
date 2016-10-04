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
"""Key wrap.

:rfc:`4357` key wrapping (28147-89 and CryptoPro).
"""

from struct import pack
from struct import unpack

from pygost.gost28147 import cfb_encrypt
from pygost.gost28147 import ecb_decrypt
from pygost.gost28147 import ecb_encrypt
from pygost.gost28147_mac import MAC


def wrap_gost(ukm, kek, cek):
    """28147-89 key wrapping

    :param ukm: UKM
    :type ukm: bytes, 8 bytes
    :param kek: key encryption key
    :type kek: bytes, 32 bytes
    :param cek: content encryption key
    :type cek: bytes, 32 bytes
    :return: wrapped key
    :rtype: bytes, 44 bytes
    """
    cek_mac = MAC(kek, data=cek, iv=ukm).digest()[:4]
    cek_enc = ecb_encrypt(kek, cek)
    return ukm + cek_enc + cek_mac


def unwrap_gost(kek, data):
    """28147-89 key unwrapping

    :param kek: key encryption key
    :type kek: bytes, 32 bytes
    :param data: wrapped key
    :type data: bytes, 44 bytes
    :return: unwrapped CEK
    :rtype: 32 bytes
    """
    if len(data) != 44:
        raise ValueError("Invalid data length")
    ukm, cek_enc, cek_mac = data[:8], data[8:8 + 32], data[-4:]
    cek = ecb_decrypt(kek, cek_enc)
    if MAC(kek, data=cek, iv=ukm).digest()[:4] != cek_mac:
        raise ValueError("Invalid MAC")
    return cek


def wrap_cryptopro(ukm, kek, cek):
    """CryptoPro key wrapping

    :param ukm: UKM
    :type ukm: bytes, 8 bytes
    :param kek: key encryption key
    :type kek: bytes, 32 bytes
    :param cek: content encryption key
    :type cek: bytes, 32 bytes
    :return: wrapped key
    :rtype: bytes, 44 bytes
    """
    return wrap_gost(ukm, diversify(kek, bytearray(ukm)), cek)


def unwrap_cryptopro(kek, data):
    """CryptoPro key unwrapping

    :param kek: key encryption key
    :type kek: bytes, 32 bytes
    :param data: wrapped key
    :type data: bytes, 44 bytes
    :return: unwrapped CEK
    :rtype: 32 bytes
    """
    if len(data) < 8:
        raise ValueError("Invalid data length")
    return unwrap_gost(diversify(kek, bytearray(data[:8])), data)


def diversify(kek, ukm):
    out = kek
    for i in range(8):
        s1, s2 = 0, 0
        for j in range(8):
            k, = unpack("<i", out[j * 4:j * 4 + 4])
            if (ukm[i] >> j) & 1:
                s1 += k
            else:
                s2 += k
        iv = pack("<I", s1 % 2 ** 32) + pack("<I", s2 % 2 ** 32)
        out = cfb_encrypt(out, out, iv=iv)
    return out
