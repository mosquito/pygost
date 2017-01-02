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
"""Key agreement functions, VKO GOST R 34.10-2001/2012
"""

from pygost.gost3410 import pub_marshal
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.gost341194 import GOST341194
from pygost.utils import bytes2long


def ukm_unmarshal(ukm):
    """Unmarshal UKM value

    :type ukm: bytes
    :rtype: long
    """
    return bytes2long(ukm[::-1])


def kek(curve, prv, pub, ukm, mode):
    key = curve.exp(prv, pub[0], pub[1])
    key = curve.exp(ukm, key[0], key[1])
    return pub_marshal(key, mode)


def kek_34102001(curve, prv, pub, ukm):
    """ Key agreement (34.10-2001, 34.11-94)

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :param pub: public key
    :type pub: (long, long)
    :param long ukm: user keying material, VKO-factor
    :returns: Key Encryption Key (shared key)
    :rtype: bytes, 32 bytes

    Shared Key Encryption Key computation is based on
    :rfc:`4357` VKO GOST R 34.10-2001 with little-endian
    hash output.
    """
    return GOST341194(
        kek(curve, prv, pub, ukm, mode=2001),
        "GostR3411_94_CryptoProParamSet",
    ).digest()


def kek_34102012256(curve, prv, pub, ukm=1):
    """ Key agreement (34.10-2012, 34.11-2012 256 bit)

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :param pub: public key
    :type pub: (long, long)
    :param long ukm: user keying material, VKO-factor
    :returns: Key Encryption Key (shared key)
    :rtype: bytes, 32 bytes

    Shared Key Encryption Key computation is based on
    :rfc:`7836` VKO GOST R 34.10-2012.
    """
    return GOST34112012256(kek(curve, prv, pub, ukm, mode=2012)).digest()


def kek_34102012512(curve, prv, pub, ukm=1):
    """ Key agreement (34.10-2012, 34.11-2012 512 bit)

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :param pub: public key
    :type pub: (long, long)
    :param long ukm: user keying material, VKO-factor
    :returns: Key Encryption Key (shared key)
    :rtype: bytes, 32 bytes

    Shared Key Encryption Key computation is based on
    :rfc:`7836` VKO GOST R 34.10-2012.
    """
    return GOST34112012512(kek(curve, prv, pub, ukm, mode=2012)).digest()
