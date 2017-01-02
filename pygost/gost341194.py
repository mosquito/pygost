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
""" GOST R 34.11-94 hash function

This is implementation of :rfc:`5831`. Most function and variable names are
taken according to specification's terminology.
"""

from copy import copy
from struct import pack

from pygost.gost28147 import addmod
from pygost.gost28147 import block2ns
from pygost.gost28147 import encrypt
from pygost.gost28147 import ns2block
from pygost.gost28147 import validate_sbox
from pygost.iface import PEP247
from pygost.utils import bytes2long
from pygost.utils import hexdec
from pygost.utils import hexenc
from pygost.utils import long2bytes
from pygost.utils import strxor
from pygost.utils import xrange  # pylint: disable=redefined-builtin


DEFAULT_SBOX = "GostR3411_94_TestParamSet"
BLOCKSIZE = 32
C2 = 32 * b"\x00"
C3 = hexdec(b"ff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00")
C4 = 32 * b"\x00"
digest_size = 32


def A(x):
    x4, x3, x2, x1 = x[0:8], x[8:16], x[16:24], x[24:32]
    return b"".join((strxor(x1, x2), x4, x3, x2))


def P(x):
    return bytearray((
        x[0], x[8], x[16], x[24], x[1], x[9], x[17], x[25], x[2],
        x[10], x[18], x[26], x[3], x[11], x[19], x[27], x[4], x[12],
        x[20], x[28], x[5], x[13], x[21], x[29], x[6], x[14], x[22],
        x[30], x[7], x[15], x[23], x[31],
    ))


def _chi(Y):
    """ Chi function

    This is some kind of LFSR.
    """
    (y16, y15, y14, y13, y12, y11, y10, y9, y8, y7, y6, y5, y4, y3, y2, y1) = (
        Y[0:2], Y[2:4], Y[4:6], Y[6:8], Y[8:10], Y[10:12], Y[12:14],
        Y[14:16], Y[16:18], Y[18:20], Y[20:22], Y[22:24], Y[24:26],
        Y[26:28], Y[28:30], Y[30:32],
    )
    by1, by2, by3, by4, by13, by16, byx = (
        bytearray(y1), bytearray(y2), bytearray(y3), bytearray(y4),
        bytearray(y13), bytearray(y16), bytearray(2),
    )
    byx[0] = by1[0] ^ by2[0] ^ by3[0] ^ by4[0] ^ by13[0] ^ by16[0]
    byx[1] = by1[1] ^ by2[1] ^ by3[1] ^ by4[1] ^ by13[1] ^ by16[1]
    return b"".join((
        bytes(byx), y16, y15, y14, y13, y12, y11, y10, y9, y8, y7, y6, y5, y4, y3, y2
    ))


def _step(hin, m, sbox):
    """ Step function

    H_out = f(H_in, m)
    """
    # Generate keys
    u = hin
    v = m
    w = strxor(hin, m)
    k1 = P(w)

    u = strxor(A(u), C2)
    v = A(A(v))
    w = strxor(u, v)
    k2 = P(w)

    u = strxor(A(u), C3)
    v = A(A(v))
    w = strxor(u, v)
    k3 = P(w)

    u = strxor(A(u), C4)
    v = A(A(v))
    w = strxor(u, v)
    k4 = P(w)

    # Encipher
    h4, h3, h2, h1 = hin[0:8], hin[8:16], hin[16:24], hin[24:32]
    s1 = ns2block(encrypt(sbox, k1[::-1], block2ns(h1[::-1])))[::-1]
    s2 = ns2block(encrypt(sbox, k2[::-1], block2ns(h2[::-1])))[::-1]
    s3 = ns2block(encrypt(sbox, k3[::-1], block2ns(h3[::-1])))[::-1]
    s4 = ns2block(encrypt(sbox, k4[::-1], block2ns(h4[::-1])))[::-1]
    s = b"".join((s4, s3, s2, s1))

    # Permute
    # H_out = chi^61(H_in XOR chi(m XOR chi^12(S)))
    x = s
    for _ in xrange(12):
        x = _chi(x)
    x = strxor(x, m)
    x = _chi(x)
    x = strxor(hin, x)
    for _ in xrange(61):
        x = _chi(x)
    return x


class GOST341194(PEP247):
    """ GOST 34.11-94 big-endian hash

    >>> m = GOST341194()
    >>> m.update("foo")
    >>> m.update("bar")
    >>> m.hexdigest()
    '3bd8a3a35917871dfa0d49f9e73e7c57eea028dc061133eb560849ea20c133af'
    >>> GOST341194("foobar").hexdigest()
    '3bd8a3a35917871dfa0d49f9e73e7c57eea028dc061133eb560849ea20c133af'
    """
    block_size = BLOCKSIZE
    digest_size = digest_size

    def __init__(self, data=b"", sbox=DEFAULT_SBOX):
        """
        :param bytes data: provide initial data
        :param bytes sbox: S-box to use
        """
        validate_sbox(sbox)
        self.data = data
        self.sbox = sbox

    def copy(self):
        return GOST341194(copy(self.data), self.sbox)

    def update(self, data):
        """ Append data that has to be hashed
        """
        self.data += data

    def digest(self):
        """ Get hash of the provided data
        """
        _len = 0
        checksum = 0
        h = 32 * b"\x00"
        m = self.data
        for i in xrange(0, len(m), BLOCKSIZE):
            part = m[i:i + BLOCKSIZE][::-1]
            _len += len(part) * 8
            checksum = addmod(checksum, int(hexenc(part), 16), 2 ** 256)
            if len(part) < BLOCKSIZE:
                part = b"\x00" * (BLOCKSIZE - len(part)) + part
            h = _step(h, part, self.sbox)
        h = _step(h, 24 * b"\x00" + pack(">Q", _len), self.sbox)

        checksum = hex(checksum)[2:].rstrip("L")
        if len(checksum) % 2 != 0:
            checksum = "0" + checksum
        checksum = hexdec(checksum)
        checksum = b"\x00" * (BLOCKSIZE - len(checksum)) + checksum
        h = _step(h, checksum, self.sbox)
        return h[::-1]


def new(data=b"", sbox=DEFAULT_SBOX):
    return GOST341194(data, sbox)


# This implementation is based on Python 3.5.2 source code's one.
# PyGOST does not register itself in hashlib anyway, so use it instead.
def pbkdf2(password, salt, iterations, dklen):
    """PBKDF2 implementation for GOST R 34.11-94

    Based on http://tc26.ru/methods/containers_v1/Addition_to_PKCS5_v1_0.pdf
    """
    inner = GOST341194(sbox="GostR3411_94_CryptoProParamSet")
    outer = GOST341194(sbox="GostR3411_94_CryptoProParamSet")
    password = password + b"\x00" * (inner.block_size - len(password))
    inner.update(strxor(password, len(password) * b"\x36"))
    outer.update(strxor(password, len(password) * b"\x5C"))

    def prf(msg):
        icpy = inner.copy()
        ocpy = outer.copy()
        icpy.update(msg)
        ocpy.update(icpy.digest())
        return ocpy.digest()

    dkey = b''
    loop = 1
    while len(dkey) < dklen:
        prev = prf(salt + long2bytes(loop, 4))
        rkey = bytes2long(prev)
        for _ in xrange(iterations - 1):
            prev = prf(prev)
            rkey ^= bytes2long(prev)
        loop += 1
        dkey += long2bytes(rkey, inner.digest_size)
    return dkey[:dklen]
