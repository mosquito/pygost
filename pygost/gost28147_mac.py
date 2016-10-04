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
""" GOST 28147-89 MAC
"""

from copy import copy

from pygost.gost28147 import block2ns
from pygost.gost28147 import BLOCKSIZE
from pygost.gost28147 import DEFAULT_SBOX
from pygost.gost28147 import ns2block
from pygost.gost28147 import validate_iv
from pygost.gost28147 import validate_key
from pygost.gost28147 import validate_sbox
from pygost.gost28147 import xcrypt
from pygost.gost3413 import pad1
from pygost.iface import PEP247
from pygost.utils import hexenc
from pygost.utils import strxor
from pygost.utils import xrange

digest_size = 8
SEQ_MAC = (
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
)


class MAC(PEP247):
    """ GOST 28147-89 MAC mode of operation

    >>> m = MAC(key=key)
    >>> m.update("some data")
    >>> m.update("another data")
    >>> m.hexdigest()[:8]
    'a687a08b'
    """
    digest_size = digest_size

    def __init__(self, key, data=b'', iv=8 * b'\x00', sbox=DEFAULT_SBOX):
        """
        :param key: authentication key
        :type key: bytes, 32 bytes
        :param iv: initialization vector
        :type iv: bytes, BLOCKSIZE length
        :param sbox: S-box parameters to use
        :type sbox: str, SBOXES'es key
        """
        validate_key(key)
        validate_iv(iv)
        validate_sbox(sbox)
        self.key = key
        self.data = data
        self.iv = iv
        self.sbox = sbox

    def copy(self):
        return MAC(self.key, copy(self.data), self.iv, self.sbox)

    def update(self, data):
        """ Append data that has to be authenticated
        """
        self.data += data

    def digest(self):
        """ Get MAC tag of supplied data

        You have to provide at least single byte of data.
        If you want to produce tag length of 3 bytes, then
        ``digest()[:3]``.
        """
        if not self.data:
            raise ValueError("No data processed")
        data = pad1(self.data, BLOCKSIZE)
        prev = block2ns(self.iv)[::-1]
        for i in xrange(0, len(data), BLOCKSIZE):
            prev = xcrypt(
                SEQ_MAC, self.sbox, self.key, block2ns(strxor(
                    data[i:i + BLOCKSIZE],
                    ns2block(prev),
                )),
            )[::-1]
        return ns2block(prev)

    def hexdigest(self):
        return hexenc(self.digest())


def new(key, data=b'', iv=8 * b'\x00', sbox=DEFAULT_SBOX):
    return MAC(key, data, iv, sbox)
