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
""" GOST 28147-89 block cipher

This is implementation of :rfc:`5830` ECB, CNT, CFB and :rfc:`4357`
CBC modes of operation. N1, N2, K names are taken according to
specification's terminology. CNT and CFB modes can work with arbitrary
data lengths.
"""

from functools import partial

from pygost.gost3413 import pad1
from pygost.gost3413 import pad2
from pygost.utils import hexdec
from pygost.utils import strxor
from pygost.utils import xrange


KEYSIZE = 32
BLOCKSIZE = 8
C1 = 0x01010104
C2 = 0x01010101

# Sequence of K_i S-box applying for encryption and decryption
SEQ_ENCRYPT = (
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    7, 6, 5, 4, 3, 2, 1, 0,
)
SEQ_DECRYPT = (
    0, 1, 2, 3, 4, 5, 6, 7,
    7, 6, 5, 4, 3, 2, 1, 0,
    7, 6, 5, 4, 3, 2, 1, 0,
    7, 6, 5, 4, 3, 2, 1, 0,
)

# S-box parameters
DEFAULT_SBOX = "Gost28147_CryptoProParamSetA"
SBOXES = {
    "Gost2814789_TestParamSet": (
        (4, 2, 15, 5, 9, 1, 0, 8, 14, 3, 11, 12, 13, 7, 10, 6),
        (12, 9, 15, 14, 8, 1, 3, 10, 2, 7, 4, 13, 6, 0, 11, 5),
        (13, 8, 14, 12, 7, 3, 9, 10, 1, 5, 2, 4, 6, 15, 0, 11),
        (14, 9, 11, 2, 5, 15, 7, 1, 0, 13, 12, 6, 10, 4, 3, 8),
        (3, 14, 5, 9, 6, 8, 0, 13, 10, 11, 7, 12, 2, 1, 15, 4),
        (8, 15, 6, 11, 1, 9, 12, 5, 13, 3, 7, 10, 0, 14, 2, 4),
        (9, 11, 12, 0, 3, 6, 7, 5, 4, 8, 14, 15, 1, 10, 2, 13),
        (12, 6, 5, 2, 11, 0, 9, 13, 3, 14, 7, 10, 15, 4, 1, 8),
    ),
    "Gost28147_CryptoProParamSetA": (
        (9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5),
        (3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1),
        (14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9),
        (14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6),
        (11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6),
        (3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6),
        (1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14),
        (11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4),
    ),
    "Gost28147_CryptoProParamSetB": (
        (8, 4, 11, 1, 3, 5, 0, 9, 2, 14, 10, 12, 13, 6, 7, 15),
        (0, 1, 2, 10, 4, 13, 5, 12, 9, 7, 3, 15, 11, 8, 6, 14),
        (14, 12, 0, 10, 9, 2, 13, 11, 7, 5, 8, 15, 3, 6, 1, 4),
        (7, 5, 0, 13, 11, 6, 1, 2, 3, 10, 12, 15, 4, 14, 9, 8),
        (2, 7, 12, 15, 9, 5, 10, 11, 1, 4, 0, 13, 6, 8, 14, 3),
        (8, 3, 2, 6, 4, 13, 14, 11, 12, 1, 7, 15, 10, 0, 9, 5),
        (5, 2, 10, 11, 9, 1, 12, 3, 7, 4, 13, 0, 6, 15, 8, 14),
        (0, 4, 11, 14, 8, 3, 7, 1, 10, 2, 9, 6, 15, 13, 5, 12),
    ),
    "Gost28147_CryptoProParamSetC": (
        (1, 11, 12, 2, 9, 13, 0, 15, 4, 5, 8, 14, 10, 7, 6, 3),
        (0, 1, 7, 13, 11, 4, 5, 2, 8, 14, 15, 12, 9, 10, 6, 3),
        (8, 2, 5, 0, 4, 9, 15, 10, 3, 7, 12, 13, 6, 14, 1, 11),
        (3, 6, 0, 1, 5, 13, 10, 8, 11, 2, 9, 7, 14, 15, 12, 4),
        (8, 13, 11, 0, 4, 5, 1, 2, 9, 3, 12, 14, 6, 15, 10, 7),
        (12, 9, 11, 1, 8, 14, 2, 4, 7, 3, 6, 5, 10, 0, 15, 13),
        (10, 9, 6, 8, 13, 14, 2, 0, 15, 3, 5, 11, 4, 1, 12, 7),
        (7, 4, 0, 5, 10, 2, 15, 14, 12, 6, 1, 11, 13, 9, 3, 8),
    ),
    "Gost28147_CryptoProParamSetD": (
        (15, 12, 2, 10, 6, 4, 5, 0, 7, 9, 14, 13, 1, 11, 8, 3),
        (11, 6, 3, 4, 12, 15, 14, 2, 7, 13, 8, 0, 5, 10, 9, 1),
        (1, 12, 11, 0, 15, 14, 6, 5, 10, 13, 4, 8, 9, 3, 7, 2),
        (1, 5, 14, 12, 10, 7, 0, 13, 6, 2, 11, 4, 9, 3, 15, 8),
        (0, 12, 8, 9, 13, 2, 10, 11, 7, 3, 6, 5, 4, 14, 15, 1),
        (8, 0, 15, 3, 2, 5, 14, 11, 1, 10, 4, 7, 12, 9, 13, 6),
        (3, 0, 6, 15, 1, 14, 9, 2, 13, 8, 12, 4, 11, 10, 5, 7),
        (1, 10, 6, 8, 15, 11, 0, 4, 12, 3, 5, 9, 7, 13, 2, 14),
    ),
    "GostR3411_94_TestParamSet": (
        (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
        (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
        (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
        (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
        (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
        (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
        (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
        (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
    ),
    "GostR3411_94_CryptoProParamSet": (
        (10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15),
        (5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8),
        (7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13),
        (4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3),
        (7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5),
        (7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3),
        (13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11),
        (1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12),
    ),
    "AppliedCryptography": (
        (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
        (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
        (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
        (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
        (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
        (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
        (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
        (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
    ),
    "Gost28147_tc26_ParamZ": (
        (12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1),
        (6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15),
        (11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0),
        (12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11),
        (7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12),
        (5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0),
        (8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7),
        (1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2),
    ),
    "EACParamSet": (
        (11, 4, 8, 10, 9, 7, 0, 3, 1, 6, 2, 15, 14, 5, 12, 13),
        (1, 7, 14, 9, 11, 3, 15, 12, 0, 5, 4, 6, 13, 10, 8, 2),
        (7, 3, 1, 9, 2, 4, 13, 15, 8, 10, 12, 6, 5, 0, 11, 14),
        (10, 5, 15, 7, 14, 11, 3, 9, 2, 8, 1, 12, 0, 4, 6, 13),
        (0, 14, 6, 11, 9, 3, 8, 4, 12, 15, 10, 5, 13, 7, 1, 2),
        (9, 2, 11, 12, 0, 4, 5, 6, 3, 15, 13, 8, 1, 7, 14, 10),
        (4, 0, 14, 1, 5, 11, 8, 3, 12, 2, 9, 7, 6, 10, 13, 15),
        (7, 14, 12, 13, 9, 4, 8, 15, 10, 2, 6, 0, 3, 11, 5, 1),
    ),
}


def _K(s, _in):
    """ S-box substitution

    :param s: S-box
    :param _in: 32-bit word
    :return: substituted 32-bit word
    """
    return (
        (s[0][(_in >> 0) & 0x0F] << 0) +
        (s[1][(_in >> 4) & 0x0F] << 4) +
        (s[2][(_in >> 8) & 0x0F] << 8) +
        (s[3][(_in >> 12) & 0x0F] << 12) +
        (s[4][(_in >> 16) & 0x0F] << 16) +
        (s[5][(_in >> 20) & 0x0F] << 20) +
        (s[6][(_in >> 24) & 0x0F] << 24) +
        (s[7][(_in >> 28) & 0x0F] << 28)
    )


def block2ns(data):
    """ Convert block to N1 and N2 integers
    """
    data = bytearray(data)
    return (
        data[0] | data[1] << 8 | data[2] << 16 | data[3] << 24,
        data[4] | data[5] << 8 | data[6] << 16 | data[7] << 24,
    )


def ns2block(ns):
    """ Convert N1 and N2 integers to 8-byte block
    """
    n1, n2 = ns
    return bytes(bytearray((
        (n2 >> 0) & 255, (n2 >> 8) & 255, (n2 >> 16) & 255, (n2 >> 24) & 255,
        (n1 >> 0) & 255, (n1 >> 8) & 255, (n1 >> 16) & 255, (n1 >> 24) & 255,
    )))


def addmod(x, y, mod=2 ** 32):
    """ Modulo adding of two integers
    """
    r = x + y
    return r if r < mod else r - mod


def _shift11(x):
    """ 11-bit cyclic shift
    """
    return ((x << 11) & (2 ** 32 - 1)) | ((x >> (32 - 11)) & (2 ** 32 - 1))


def validate_key(key):
    if len(key) != KEYSIZE:
        raise ValueError("Invalid key size")


def validate_iv(iv):
    if len(iv) != BLOCKSIZE:
        raise ValueError("Invalid IV size")


def validate_sbox(sbox):
    if sbox not in SBOXES:
        raise ValueError("Unknown sbox supplied")


def xcrypt(seq, sbox, key, ns):
    """ Perform full-round single-block operation

    :param seq: sequence of K_i S-box applying (either encrypt or decrypt)
    :param sbox: S-box parameters to use
    :type sbox: str, SBOXES'es key
    :param bytes key: 256-bit encryption key
    :param ns: N1 and N2 integers
    :type ns: (int, int)
    :return: resulting N1 and N2
    :rtype: (int, int)
    """
    s = SBOXES[sbox]
    w = bytearray(key)
    x = [
        w[0 + i * 4] |
        w[1 + i * 4] << 8 |
        w[2 + i * 4] << 16 |
        w[3 + i * 4] << 24 for i in range(8)
    ]
    n1, n2 = ns
    for i in seq:
        n1, n2 = _shift11(_K(s, addmod(n1, x[i]))) ^ n2, n1
    return n1, n2


def encrypt(sbox, key, ns):
    """ Encrypt single block
    """
    return xcrypt(SEQ_ENCRYPT, sbox, key, ns)


def decrypt(sbox, key, ns):
    """ Decrypt single block
    """
    return xcrypt(SEQ_DECRYPT, sbox, key, ns)


def ecb(key, data, action, sbox=DEFAULT_SBOX):
    """ ECB mode of operation

    :param bytes key: encryption key
    :param data: plaintext
    :type data: bytes, multiple of BLOCKSIZE
    :param func action: encrypt/decrypt
    :param sbox: S-box parameters to use
    :type sbox: str, SBOXES'es key
    :return: ciphertext
    :rtype: bytes
    """
    validate_key(key)
    validate_sbox(sbox)
    if not data or len(data) % BLOCKSIZE != 0:
        raise ValueError("Data is not blocksize aligned")
    result = []
    for i in xrange(0, len(data), BLOCKSIZE):
        result.append(ns2block(action(
            sbox, key, block2ns(data[i:i + BLOCKSIZE])
        )))
    return b''.join(result)


ecb_encrypt = partial(ecb, action=encrypt)
ecb_decrypt = partial(ecb, action=decrypt)


def cbc_encrypt(key, data, iv=8 * b'\x00', pad=True, sbox=DEFAULT_SBOX):
    """ CBC encryption mode of operation

    :param bytes key: encryption key
    :param bytes data: plaintext
    :param iv: initialization vector
    :type iv: bytes, BLOCKSIZE length
    :type bool pad: perform ISO/IEC 7816-4 padding
    :param sbox: S-box parameters to use
    :type sbox: str, SBOXES'es key
    :return: ciphertext
    :rtype: bytes

    34.13-2015 padding method 2 is used.
    """
    validate_key(key)
    validate_iv(iv)
    validate_sbox(sbox)
    if not data:
        raise ValueError("No data supplied")
    if pad:
        data = pad2(data, BLOCKSIZE)
    if len(data) % BLOCKSIZE != 0:
        raise ValueError("Data is not blocksize aligned")
    ciphertext = [iv]
    for i in xrange(0, len(data), BLOCKSIZE):
        ciphertext.append(ns2block(encrypt(sbox, key, block2ns(
            strxor(ciphertext[-1], data[i:i + BLOCKSIZE])
        ))))
    return b''.join(ciphertext)


def cbc_decrypt(key, data, pad=True, sbox=DEFAULT_SBOX):
    """ CBC decryption mode of operation

    :param bytes key: encryption key
    :param bytes data: ciphertext
    :param iv: initialization vector
    :type iv: bytes, BLOCKSIZE length
    :type bool pad: perform ISO/IEC 7816-4 unpadding after decryption
    :param sbox: S-box parameters to use
    :type sbox: str, SBOXES'es key
    :return: plaintext
    :rtype: bytes
    """
    validate_key(key)
    validate_sbox(sbox)
    if not data or len(data) % BLOCKSIZE != 0:
        raise ValueError("Data is not blocksize aligned")
    if len(data) < 2 * BLOCKSIZE:
        raise ValueError("There is no either data, or IV in ciphertext")
    plaintext = []
    for i in xrange(BLOCKSIZE, len(data), BLOCKSIZE):
        plaintext.append(strxor(
            ns2block(decrypt(sbox, key, block2ns(data[i:i + BLOCKSIZE]))),
            data[i - BLOCKSIZE:i],
        ))
    if pad:
        last_block = bytearray(plaintext[-1])
        pad_index = last_block.rfind(b'\x80')
        if pad_index == -1:
            raise ValueError("Invalid padding")
        for c in last_block[pad_index + 1:]:
            if c != 0:
                raise ValueError("Invalid padding")
        plaintext[-1] = bytes(last_block[:pad_index])
    return b''.join(plaintext)


def cnt(key, data, iv=8 * b'\x00', sbox=DEFAULT_SBOX):
    """ Counter mode of operation

    :param bytes key: encryption key
    :param bytes data: plaintext
    :param iv: initialization vector
    :type iv: bytes, BLOCKSIZE length
    :param sbox: S-box parameters to use
    :type sbox: str, SBOXES'es key
    :return: ciphertext
    :rtype: bytes

    For decryption you use the same function again.
    """
    validate_key(key)
    validate_iv(iv)
    validate_sbox(sbox)
    if not data:
        raise ValueError("No data supplied")
    n2, n1 = encrypt(sbox, key, block2ns(iv))
    size = len(data)
    data = pad1(data, BLOCKSIZE)
    gamma = []
    for _ in xrange(0, len(data), BLOCKSIZE):
        n1 = addmod(n1, C2, 2 ** 32)
        n2 = addmod(n2, C1, 2 ** 32 - 1)
        gamma.append(ns2block(encrypt(sbox, key, (n1, n2))))
    return strxor(b''.join(gamma), data[:size])


MESH_CONST = hexdec("6900722264C904238D3ADB9646E92AC418FEAC9400ED0712C086DCC2EF4CA92B")
MESH_MAX_DATA = 1024


def meshing(key, iv, sbox=DEFAULT_SBOX):
    """:rfc:`4357` key meshing
    """
    key = ecb_decrypt(key, MESH_CONST, sbox=sbox)
    iv = ecb_encrypt(key, iv, sbox=sbox)
    return key, iv


def cfb_encrypt(key, data, iv=8 * b'\x00', sbox=DEFAULT_SBOX, mesh=False):
    """ CFB encryption mode of operation

    :param bytes key: encryption key
    :param bytes data: plaintext
    :param iv: initialization vector
    :type iv: bytes, BLOCKSIZE length
    :param sbox: S-box parameters to use
    :type sbox: str, SBOXES'es key
    :param bool mesh: enable key meshing
    :return: ciphertext
    :rtype: bytes
    """
    validate_key(key)
    validate_iv(iv)
    validate_sbox(sbox)
    if not data:
        raise ValueError("No data supplied")
    size = len(data)
    data = pad1(data, BLOCKSIZE)
    ciphertext = [iv]
    for i in xrange(0, len(data), BLOCKSIZE):
        if mesh and i >= MESH_MAX_DATA and i % MESH_MAX_DATA == 0:
            key, iv = meshing(key, ciphertext[-1], sbox=sbox)
            ciphertext.append(strxor(
                data[i:i + BLOCKSIZE],
                ns2block(encrypt(sbox, key, block2ns(iv))),
            ))
            continue
        ciphertext.append(strxor(
            data[i:i + BLOCKSIZE],
            ns2block(encrypt(sbox, key, block2ns(ciphertext[-1]))),
        ))
    return b''.join(ciphertext[1:])[:size]


def cfb_decrypt(key, data, iv=8 * b'\x00', sbox=DEFAULT_SBOX, mesh=False):
    """ CFB decryption mode of operation

    :param bytes key: encryption key
    :param bytes data: plaintext
    :param iv: initialization vector
    :type iv: bytes, BLOCKSIZE length
    :param sbox: S-box parameters to use
    :type sbox: str, SBOXES'es key
    :param bool mesh: enable key meshing
    :return: ciphertext
    :rtype: bytes
    """
    validate_key(key)
    validate_iv(iv)
    validate_sbox(sbox)
    if not data:
        raise ValueError("No data supplied")
    size = len(data)
    data = pad1(data, BLOCKSIZE)
    plaintext = []
    data = iv + data
    for i in xrange(BLOCKSIZE, len(data), BLOCKSIZE):
        if (
                mesh and
                (i - BLOCKSIZE) >= MESH_MAX_DATA and
                (i - BLOCKSIZE) % MESH_MAX_DATA == 0
        ):
            key, iv = meshing(key, data[i - BLOCKSIZE:i], sbox=sbox)
            plaintext.append(strxor(
                data[i:i + BLOCKSIZE],
                ns2block(encrypt(sbox, key, block2ns(iv))),
            ))
            continue
        plaintext.append(strxor(
            data[i:i + BLOCKSIZE],
            ns2block(encrypt(sbox, key, block2ns(data[i - BLOCKSIZE:i]))),
        ))
    return b''.join(plaintext)[:size]
