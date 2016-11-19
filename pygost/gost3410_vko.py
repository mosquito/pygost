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
"""Diffie-Hellman functions, VKO GOST R 34.10-2001/2012
"""

from pygost.gost3410 import pub_marshal
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.gost341194 import GOST341194
from pygost.utils import bytes2long


def vko_34102001(curve, prv, pubkey, ukm):
    """ Make Diffie-Hellman computation (34.10-2001, 34.11-94)

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :param pubkey: public key
    :type pubkey: (long, long)
    :param ukm: UKM value (VKO-factor)
    :type ukm: bytes, 8 bytes
    :returns: Key Encryption Key (shared key)
    :rtype: bytes, 32 bytes

    Shared Key Encryption Key computation is based on
    :rfc:`4357` VKO GOST R 34.10-2001 with little-endian
    hash output.
    """
    key = curve.exp(prv, pubkey[0], pubkey[1])
    key = curve.exp(bytes2long(24 * b"\x00" + ukm), key[0], key[1])
    return GOST341194(pub_marshal(key), "GostR3411_94_CryptoProParamSet").digest()


def vko_34102012256(curve, prv, pubkey, ukm=b"\x00\x00\x00\x00\x00\x00\x00\01"):
    """ Make Diffie-Hellman computation (34.10-2012, 34.11-2012 256 bit)

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :param pubkey: public key
    :type pubkey: (long, long)
    :param ukm: UKM value (VKO-factor)
    :type ukm: bytes, 8 bytes
    :returns: Key Encryption Key (shared key)
    :rtype: bytes, 32 bytes
    """
    key = curve.exp(prv, pubkey[0], pubkey[1])
    key = curve.exp(bytes2long(ukm[::-1]), key[0], key[1])
    return GOST34112012256(pub_marshal(key, mode=2012)).digest()


def vko_34102012512(curve, prv, pubkey, ukm=b"\x00\x00\x00\x00\x00\x00\x00\01"):
    """ Make Diffie-Hellman computation (34.10-2012, 34.11-2012 512 bit)

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :param pubkey: public key
    :type pubkey: (long, long)
    :param ukm: UKM value (VKO-factor)
    :type ukm: bytes, 8 bytes
    :returns: Key Encryption Key (shared key)
    :rtype: bytes, 32 bytes
    """
    key = curve.exp(prv, pubkey[0], pubkey[1])
    key = curve.exp(bytes2long(ukm[::-1]), key[0], key[1])
    return GOST34112012512(pub_marshal(key, mode=2012)).digest()
