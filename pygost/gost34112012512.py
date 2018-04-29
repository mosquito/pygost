""" GOST R 34.11-2012 (Streebog) 512-bit hash function

This is implementation of :rfc:`6986`. Most function and variable names are
taken according to specification's terminology.
"""

from pygost.gost34112012 import GOST34112012
from pygost.pbkdf2 import pbkdf2 as pbkdf2_base


class GOST34112012512(GOST34112012):
    def __init__(self, data=b''):
        super(GOST34112012512, self).__init__(data, digest_size=64)


def new(data=b''):
    return GOST34112012512(data)


def pbkdf2(password, salt, iterations, dklen):
    return pbkdf2_base(GOST34112012512, password, salt, iterations, dklen)
