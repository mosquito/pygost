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
""" GOST R 34.10 public-key signature function.

This is implementation of GOST R 34.10-2001 (:rfc:`5832`), GOST R
34.10-2012 (:rfc:`7091`). The difference between 2001 and 2012 is the
key, digest and signature lengths.
"""

from os import urandom

from pygost.utils import bytes2long
from pygost.utils import hexdec
from pygost.utils import long2bytes
from pygost.utils import modinvert


MODE2SIZE = {
    2001: 32,
    2012: 64,
}


DEFAULT_CURVE = "GostR3410_2001_CryptoPro_A_ParamSet"
# Curve parameters are the following: p, q, a, b, x, y
CURVE_PARAMS = {
    "GostR3410_2001_ParamSet_cc": (
        "C0000000000000000000000000000000000000000000000000000000000003C7",
        "5fffffffffffffffffffffffffffffff606117a2f4bde428b7458a54b6e87b85",
        "C0000000000000000000000000000000000000000000000000000000000003c4",
        "2d06B4265ebc749ff7d0f1f1f88232e81632e9088fd44b7787d5e407e955080c",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "a20e034bf8813ef5c18d01105e726a17eb248b264ae9706f440bedc8ccb6b22c",
    ),
    "GostR3410_2001_TestParamSet": (
        "8000000000000000000000000000000000000000000000000000000000000431",
        "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8",
    ),
    "GostR3410_2001_CryptoPro_A_ParamSet": (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
        "00000000000000000000000000000000000000000000000000000000000000a6",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
    ),
    "GostR3410_2001_CryptoPro_B_ParamSet": (
        "8000000000000000000000000000000000000000000000000000000000000C99",
        "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
        "8000000000000000000000000000000000000000000000000000000000000C96",
        "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC",
    ),
    "GostR3410_2001_CryptoPro_C_ParamSet": (
        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
        "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
        "000000000000000000000000000000000000000000000000000000000000805a",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67",
    ),
    "GostR3410_2001_CryptoPro_XchA_ParamSet": (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
        "00000000000000000000000000000000000000000000000000000000000000a6",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
    ),
    "GostR3410_2001_CryptoPro_XchB_ParamSet": (
        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
        "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
        "000000000000000000000000000000000000000000000000000000000000805a",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67",
    ),
    # pylint: disable=line-too-long
    "GostR3410_2012_TC26_ParamSetA": (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
        "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
        "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
    ),
    "GostR3410_2012_TC26_ParamSetB": (
        "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
        "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
        "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
        "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
        "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"
    ),
    # pylint: enable=line-too-long
}
for c, params in CURVE_PARAMS.items():
    CURVE_PARAMS[c] = [hexdec(param) for param in params]


class GOST3410Curve(object):
    """ GOST 34.10 validated curve

    >>> p, q, a, b, x, y = CURVE_PARAMS["GostR3410_2001_TestParamSet"]
    >>> curve = GOST3410Curve(p, q, a, b, x, y)
    >>> prv = prv_unmarshal(urandom(32))
    >>> signature = sign(curve, prv, GOST341194(data).digest())
    >>> pub = public_key(curve, prv)
    >>> verify(curve, pub, GOST341194(data).digest(), signature)
    True
    """
    def __init__(self, p, q, a, b, x, y):
        self.p = bytes2long(p)
        self.q = bytes2long(q)
        self.a = bytes2long(a)
        self.b = bytes2long(b)
        self.x = bytes2long(x)
        self.y = bytes2long(y)
        r1 = self.y * self.y % self.p
        r2 = ((self.x * self.x + self.a) * self.x + self.b) % self.p
        if r2 < 0:
            r2 += self.p
        if r1 != r2:
            raise ValueError("Invalid parameters")

    def _pos(self, v):
        if v < 0:
            return v + self.p
        return v

    def _add(self, p1x, p1y, p2x, p2y):
        if p1x == p2x and p1y == p2y:
            # double
            t = ((3 * p1x * p1x + self.a) * modinvert(2 * p1y, self.p)) % self.p
        else:
            tx = self._pos(p2x - p1x) % self.p
            ty = self._pos(p2y - p1y) % self.p
            t = (ty * modinvert(tx, self.p)) % self.p
        tx = self._pos(t * t - p1x - p2x) % self.p
        ty = self._pos(t * (p1x - tx) - p1y) % self.p
        return tx, ty

    def exp(self, degree, x=None, y=None):
        x = x or self.x
        y = y or self.y
        tx = x
        ty = y
        degree -= 1
        if degree == 0:
            raise ValueError("Bad degree value")
        while degree != 0:
            if degree & 1 == 1:
                tx, ty = self._add(tx, ty, x, y)
            degree = degree >> 1
            x, y = self._add(x, y, x, y)
        return tx, ty


def public_key(curve, prv):
    """ Generate public key from the private one

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :returns: public key's parts, X and Y
    :rtype: (long, long)
    """
    return curve.exp(prv)


def sign(curve, prv, digest, mode=2001):
    """ Calculate signature for provided digest

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :param digest: digest for signing
    :type digest: bytes, 32 or 64 bytes
    :returns: signature
    :rtype: bytes, 64 or 128 bytes
    """
    size = MODE2SIZE[mode]
    q = curve.q
    e = bytes2long(digest) % q
    if e == 0:
        e = 1
    while True:
        k = bytes2long(urandom(size)) % q
        if k == 0:
            continue
        r, _ = curve.exp(k)
        r %= q
        if r == 0:
            continue
        d = prv * r
        k *= e
        s = (d + k) % q
        if s == 0:
            continue
        break
    return long2bytes(s, size) + long2bytes(r, size)


def verify(curve, pub, digest, signature, mode=2001):
    """ Verify provided digest with the signature

    :param GOST3410Curve curve: curve to use
    :type pub: (long, long)
    :param digest: digest needed to check
    :type digest: bytes, 32 or 64 bytes
    :param signature: signature to verify with
    :type signature: bytes, 64 or 128 bytes
    :rtype: bool
    """
    size = MODE2SIZE[mode]
    if len(signature) != size * 2:
        raise ValueError("Invalid signature length")
    q = curve.q
    p = curve.p
    s = bytes2long(signature[:size])
    r = bytes2long(signature[size:])
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    e = bytes2long(digest) % curve.q
    if e == 0:
        e = 1
    v = modinvert(e, q)
    z1 = s * v % q
    z2 = q - r * v % q
    p1x, p1y = curve.exp(z1)
    q1x, q1y = curve.exp(z2, pub[0], pub[1])
    lm = q1x - p1x
    if lm < 0:
        lm += p
    lm = modinvert(lm, p)
    z1 = q1y - p1y
    lm = lm * z1 % p
    lm = lm * lm % p
    lm = lm - p1x - q1x
    lm = lm % p
    if lm < 0:
        lm += p
    lm %= q
    # This is not constant time comparison!
    return lm == r


def prv_unmarshal(prv):
    """Unmarshal private key

    :param bytes prv: serialized private key
    :rtype: long
    """
    return bytes2long(prv[::-1])


def pub_marshal(pub, mode=2001):
    """Marshal public key

    :type pub: (long, long)
    :rtype: bytes
    """
    size = MODE2SIZE[mode]
    return (long2bytes(pub[1], size) + long2bytes(pub[0], size))[::-1]


def pub_unmarshal(pub, mode=2001):
    """Unmarshal public key

    :type pub: bytes
    :rtype: (long, long)
    """
    size = MODE2SIZE[mode]
    pub = pub[::-1]
    return (bytes2long(pub[size:]), bytes2long(pub[:size]))
