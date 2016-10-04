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
""" :rfc:`4491` (using GOST algorithms with X.509) compatibility helpers

Signature, public and private keys formats are defined in the RFC above.
"""

from pygost.gost3410 import CURVE_PARAMS
from pygost.gost3410 import GOST3410Curve
from pygost.gost3410 import public_key as _public_key
from pygost.gost3410 import sign as _sign
from pygost.gost3410 import SIZE_3410_2001
from pygost.gost3410 import SIZE_3410_2012
from pygost.gost3410 import verify as _verify
from pygost.gost3411_2012 import GOST34112012
from pygost.gost3411_94 import GOST341194
from pygost.utils import bytes2long
from pygost.utils import long2bytes


GOST341194_SBOX = "GostR3411_94_CryptoProParamSet"
MODE2PARAMS = {
    2001: "GostR3410_2001_CryptoPro_A_ParamSet",
    2012: "GostR3410_2012_TC26_ParamSetA",
}
MODE2SIZE = {
    2001: SIZE_3410_2001,
    2012: SIZE_3410_2012,
}
MODE2DIGEST = {
    2001: lambda data: GOST341194(data, sbox=GOST341194_SBOX).digest(),
    2012: lambda data: GOST34112012(data).digest(),
}


def keypair_gen(seed, mode=2001, curve_params=None):
    """ Generate keypair

    :param bytes seed: random data used as an entropy source
    :param int mode: either 2001 or 2012
    :param str curve_params: :py:data:`gost3410.CURVE_PARAMS` key identifying
                             curve parameters. GostR3410_2001_CryptoPro_A_ParamSet
                             will be used by default for 2001 mode and
                             GostR3410_2012_TC26_ParamSetA for 2012 one.
    :return: private and public keys
    :rtype: (bytes, bytes), 32/64 and 64/128 bytes
    """
    if len(seed) != MODE2SIZE[mode]:
        raise ValueError("Invalid seed size")
    curve_params = curve_params or MODE2PARAMS[mode]
    curve = GOST3410Curve(*CURVE_PARAMS[curve_params])
    private_key = seed
    public_key_x, public_key_y = _public_key(curve, bytes2long(private_key))
    public_key = (long2bytes(public_key_y) + long2bytes(public_key_x))[::-1]
    return private_key[::-1], public_key


def sign_digest(private_key, digest, mode=2001, curve_params=None):
    """ Sign digest

    :param bytes private_key: private key to sign with
    :param bytes digest: precalculated digest
    :param int mode: either 2001 or 2012
    :param str curve_params: :py:data:`gost3410.CURVE_PARAMS` key identifying
                             curve parameters. GostR3410_2001_CryptoPro_A_ParamSet
                             will be used by default for 2001 mode and
                             GostR3410_2012_TC26_ParamSetA for 2012 one.
    :return: signature
    :rtype: bytes, 64/128 bytes
    """
    curve_params = curve_params or MODE2PARAMS[mode]
    curve = GOST3410Curve(*CURVE_PARAMS[curve_params])
    return _sign(
        curve,
        bytes2long(private_key[::-1]),
        digest,
        size=MODE2SIZE[mode],
    )


def verify_digest(public_key, digest, signature, mode=2001, curve_params=None):
    """ Verify signature of the digest

    :param bytes public_key: public key to verify with
    :param bytes digest: precalculated digest
    :param bytes signature: signature
    :param int mode: either 2001 or 2012
    :param str curve_params: :py:data:`gost3410.CURVE_PARAMS` key identifying
                             curve parameters. GostR3410_2001_CryptoPro_A_ParamSet
                             will be used by default for 2001 mode and
                             GostR3410_2012_TC26_ParamSetA for 2012 one.
    :rtype: bool
    """
    curve_params = curve_params or MODE2PARAMS[mode]
    curve = GOST3410Curve(*CURVE_PARAMS[curve_params])
    public_key = public_key[::-1]
    size = MODE2SIZE[mode]
    return _verify(
        curve,
        bytes2long(public_key[size:]),
        bytes2long(public_key[:size]),
        digest,
        signature,
        size=MODE2SIZE[mode],
    )


def sign(private_key, data, mode=2001, curve_params=None):
    """ Calculate data's digest and sign it

    :param bytes private_key: private key to sign with
    :param bytes data: arbitrary data
    :param int mode: either 2001 or 2012
    :param str curve_params: :py:data:`gost3410.CURVE_PARAMS` key identifying
                             curve parameters. GostR3410_2001_CryptoPro_A_ParamSet
                             will be used by default for 2001 mode and
                             GostR3410_2012_TC26_ParamSetA for 2012 one.
    :return: signature
    :rtype: bytes, 64/128 bytes
    """
    return sign_digest(private_key, MODE2DIGEST[mode](data), mode, curve_params)


def verify(public_key, data, signature, mode=2001, curve_params=None):
    """ Verify signature of the digest

    :param bytes public_key: public key to verify with
    :param bytes digest: precalculated digest
    :param bytes signature: signature
    :param int mode: either 2001 or 2012
    :param str curve_params: :py:data:`gost3410.CURVE_PARAMS` key identifying
                             curve parameters. GostR3410_2001_CryptoPro_A_ParamSet
                             will be used by default for 2001 mode and
                             GostR3410_2012_TC26_ParamSetA for 2012 one.
    :rtype: bool
    """
    return verify_digest(
        public_key,
        MODE2DIGEST[mode](data),
        signature,
        mode,
        curve_params,
    )
