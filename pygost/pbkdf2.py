# coding: utf-8
""" PBKDF2 implementation suitable for GOST R 34.11-94/34.11-2012.

This implementation is based on Python 3.5.2 source code's one.
PyGOST does not register itself in hashlib anyway, so use it instead.
"""


from pygost.utils import bytes2long
from pygost.utils import long2bytes
from pygost.utils import strxor
from pygost.utils import xrange  # pylint: disable=redefined-builtin


def pbkdf2(hasher, password, salt, iterations, dklen):
    """PBKDF2 implementation suitable for GOST R 34.11-94/34.11-2012
    """
    inner = hasher()
    outer = hasher()
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
