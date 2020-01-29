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

from pyderasn import Any
from pyderasn import BitString
from pyderasn import Choice
from pyderasn import Integer
from pyderasn import Null
from pyderasn import ObjectIdentifier
from pyderasn import OctetString
from pyderasn import Sequence
from pyderasn import tag_ctxc

from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512
from pygost.asn1schemas.x509 import GostR34102012PublicKeyParameters


class ECParameters(Choice):
    schema = (
        ("namedCurve", ObjectIdentifier()),
        ("implicitCurve", Null()),
        # ("specifiedCurve", SpecifiedECDomain()),
    )


ecPrivkeyVer1 = Integer(1)


class ECPrivateKey(Sequence):
    schema = (
        ("version", Integer(ecPrivkeyVer1)),
        ("privateKey", OctetString()),
        ("parameters", ECParameters(expl=tag_ctxc(0), optional=True)),
        ("publicKey", BitString(expl=tag_ctxc(1), optional=True)),
    )


class PrivateKeyAlgorithmIdentifier(Sequence):
    schema = (
        ("algorithm", ObjectIdentifier(defines=(
            (("parameters",), {
                id_tc26_gost3410_2012_256: GostR34102012PublicKeyParameters(),
                id_tc26_gost3410_2012_512: GostR34102012PublicKeyParameters(),
            }),
        ))),
        ("parameters", Any(optional=True)),
    )


class PrivateKey(OctetString):
    pass


class PrivateKeyInfo(Sequence):
    schema = (
        ("version", Integer(0)),
        ("privateKeyAlgorithm", PrivateKeyAlgorithmIdentifier()),
        ("privateKey", PrivateKey()),
    )
