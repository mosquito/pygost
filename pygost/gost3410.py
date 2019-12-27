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


class GOST3410Curve(object):
    """ GOST 34.10 validated curve

    >>> curve = CURVES["id-GostR3410-2001-TestParamSet"]
    >>> prv = prv_unmarshal(urandom(32))
    >>> signature = sign(curve, prv, GOST341194(data).digest())
    >>> pub = public_key(curve, prv)
    >>> verify(curve, pub, GOST341194(data).digest(), signature)
    True

    :param long p: characteristic of the underlying prime field
    :param long q: elliptic curve subgroup order
    :param long a, b: coefficients of the equation of the elliptic curve in
                      the canonical form
    :param long x, y: the coordinate of the point P (generator of the
                      subgroup of order q) of the elliptic curve in
                      the canonical form
    :param long e, d: coefficients of the equation of the elliptic curve in
                      the twisted Edwards form
    """
    def __init__(self, p, q, a, b, x, y, e=None, d=None):
        self.p = p
        self.q = q
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        self.e = e
        self.d = d
        r1 = self.y * self.y % self.p
        r2 = ((self.x * self.x + self.a) * self.x + self.b) % self.p
        if r1 != self.pos(r2):
            raise ValueError("Invalid parameters")
        self._st = None

    def pos(self, v):
        """Make positive number
        """
        if v < 0:
            return v + self.p
        return v

    def _add(self, p1x, p1y, p2x, p2y):
        if p1x == p2x and p1y == p2y:
            # double
            t = ((3 * p1x * p1x + self.a) * modinvert(2 * p1y, self.p)) % self.p
        else:
            tx = self.pos(p2x - p1x) % self.p
            ty = self.pos(p2y - p1y) % self.p
            t = (ty * modinvert(tx, self.p)) % self.p
        tx = self.pos(t * t - p1x - p2x) % self.p
        ty = self.pos(t * (p1x - tx) - p1y) % self.p
        return tx, ty

    def exp(self, degree, x=None, y=None):
        x = x or self.x
        y = y or self.y
        tx = x
        ty = y
        if degree == 0:
            raise ValueError("Bad degree value")
        degree -= 1
        while degree != 0:
            if degree & 1 == 1:
                tx, ty = self._add(tx, ty, x, y)
            degree = degree >> 1
            x, y = self._add(x, y, x, y)
        return tx, ty

    def st(self):
        """Compute s/t parameters for twisted Edwards curve points conversion
        """
        if self.e is None or self.d is None:
            raise ValueError("non twisted Edwards curve")
        if self._st is not None:
            return self._st
        self._st = (
            self.pos(self.e - self.d) * modinvert(4, self.p) % self.p,
            (self.e + self.d) * modinvert(6, self.p) % self.p,
        )
        return self._st


CURVES = {
    "GostR3410_2001_ParamSet_cc": GOST3410Curve(
        p=bytes2long(hexdec("C0000000000000000000000000000000000000000000000000000000000003C7")),
        q=bytes2long(hexdec("5fffffffffffffffffffffffffffffff606117a2f4bde428b7458a54b6e87b85")),
        a=bytes2long(hexdec("C0000000000000000000000000000000000000000000000000000000000003c4")),
        b=bytes2long(hexdec("2d06B4265ebc749ff7d0f1f1f88232e81632e9088fd44b7787d5e407e955080c")),
        x=bytes2long(hexdec("0000000000000000000000000000000000000000000000000000000000000002")),
        y=bytes2long(hexdec("a20e034bf8813ef5c18d01105e726a17eb248b264ae9706f440bedc8ccb6b22c")),
    ),
    "id-GostR3410-2001-TestParamSet": GOST3410Curve(
        p=bytes2long(hexdec("8000000000000000000000000000000000000000000000000000000000000431")),
        q=bytes2long(hexdec("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3")),
        a=bytes2long(hexdec("0000000000000000000000000000000000000000000000000000000000000007")),
        b=bytes2long(hexdec("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E")),
        x=bytes2long(hexdec("0000000000000000000000000000000000000000000000000000000000000002")),
        y=bytes2long(hexdec("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8")),
    ),
    "id-GostR3410-2001-CryptoPro-A-ParamSet": GOST3410Curve(
        p=bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97")),
        q=bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893")),
        a=bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94")),
        b=bytes2long(hexdec("00000000000000000000000000000000000000000000000000000000000000a6")),
        x=bytes2long(hexdec("0000000000000000000000000000000000000000000000000000000000000001")),
        y=bytes2long(hexdec("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14")),
    ),
    "id-GostR3410-2001-CryptoPro-B-ParamSet": GOST3410Curve(
        p=bytes2long(hexdec("8000000000000000000000000000000000000000000000000000000000000C99")),
        q=bytes2long(hexdec("800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F")),
        a=bytes2long(hexdec("8000000000000000000000000000000000000000000000000000000000000C96")),
        b=bytes2long(hexdec("3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B")),
        x=bytes2long(hexdec("0000000000000000000000000000000000000000000000000000000000000001")),
        y=bytes2long(hexdec("3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC")),
    ),
    "id-GostR3410-2001-CryptoPro-C-ParamSet": GOST3410Curve(
        p=bytes2long(hexdec("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B")),
        q=bytes2long(hexdec("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9")),
        a=bytes2long(hexdec("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598")),
        b=bytes2long(hexdec("000000000000000000000000000000000000000000000000000000000000805a")),
        x=bytes2long(hexdec("0000000000000000000000000000000000000000000000000000000000000000")),
        y=bytes2long(hexdec("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67")),
    ),
    "id-tc26-gost-3410-2012-256-paramSetA": GOST3410Curve(
        p=bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97")),
        q=bytes2long(hexdec("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67")),
        a=bytes2long(hexdec("C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335")),
        b=bytes2long(hexdec("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513")),
        x=bytes2long(hexdec("91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28")),
        y=bytes2long(hexdec("32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C")),
        e=0x01,
        d=bytes2long(hexdec("0605F6B7C183FA81578BC39CFAD518132B9DF62897009AF7E522C32D6DC7BFFB")),
    ),
    "id-tc26-gost-3410-12-512-paramSetA": GOST3410Curve(
        p=bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7")),
        q=bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275")),
        a=bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4")),
        b=bytes2long(hexdec("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760")),
        x=bytes2long(hexdec("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003")),
        y=bytes2long(hexdec("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4")),
    ),
    "id-tc26-gost-3410-12-512-paramSetB": GOST3410Curve(
        p=bytes2long(hexdec("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F")),
        q=bytes2long(hexdec("800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD")),
        a=bytes2long(hexdec("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C")),
        b=bytes2long(hexdec("687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116")),
        x=bytes2long(hexdec("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002")),
        y=bytes2long(hexdec("1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD")),
    ),
    "id-tc26-gost-3410-2012-512-paramSetC": GOST3410Curve(
        p=bytes2long(hexdec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7")),
        q=bytes2long(hexdec("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED")),
        a=bytes2long(hexdec("DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3")),
        b=bytes2long(hexdec("B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1")),
        x=bytes2long(hexdec("E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148")),
        y=bytes2long(hexdec("F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F")),
        e=0x01,
        d=bytes2long(hexdec("9E4F5D8C017D8D9F13A5CF3CDF5BFE4DAB402D54198E31EBDE28A0621050439CA6B39E0A515C06B304E2CE43E79E369E91A0CFC2BC2A22B4CA302DBB33EE7550")),
    ),
}
CURVES["id-GostR3410-2001-CryptoPro-XchA-ParamSet"] = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"]
CURVES["id-GostR3410-2001-CryptoPro-XchB-ParamSet"] = CURVES["id-GostR3410-2001-CryptoPro-C-ParamSet"]
CURVES["id-tc26-gost-3410-2012-256-paramSetB"] = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"]
CURVES["id-tc26-gost-3410-2012-256-paramSetC"] = CURVES["id-GostR3410-2001-CryptoPro-B-ParamSet"]
CURVES["id-tc26-gost-3410-2012-256-paramSetD"] = CURVES["id-GostR3410-2001-CryptoPro-C-ParamSet"]
DEFAULT_CURVE = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"]


def public_key(curve, prv):
    """ Generate public key from the private one

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :returns: public key's parts, X and Y
    :rtype: (long, long)
    """
    return curve.exp(prv)


def sign(curve, prv, digest, rand=None, mode=2001):
    """ Calculate signature for provided digest

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :param digest: digest for signing
    :type digest: bytes, 32 or 64 bytes
    :param rand: optional predefined random data used for k/r generation
    :type rand: bytes, 32 or 64 bytes
    :returns: signature
    :rtype: bytes, 64 or 128 bytes
    """
    size = MODE2SIZE[mode]
    q = curve.q
    e = bytes2long(digest) % q
    if e == 0:
        e = 1
    while True:
        if rand is None:
            rand = urandom(size)
        elif len(rand) != size:
            raise ValueError("rand length != %d" % size)
        k = bytes2long(rand) % q
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


def uv2xy(curve, u, v):
    """Convert twisted Edwards curve U,V coordinates to Weierstrass X,Y
    """
    s, t = curve.st()
    k1 = (s * (1 + v)) % curve.p
    k2 = curve.pos(1 - v)
    x = t + k1 * modinvert(k2, curve.p)
    y = k1 * modinvert(u * k2, curve.p)
    return x % curve.p, y % curve.p


def xy2uv(curve, x, y):
    """Convert Weierstrass X,Y coordinates to twisted Edwards curve U,V
    """
    s, t = curve.st()
    xmt = curve.pos(x - t)
    u = xmt * modinvert(y, curve.p)
    v = curve.pos(xmt - s) * modinvert(xmt + s, curve.p)
    return u % curve.p, v % curve.p
