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
"""PKCS #10 related structures (**NOT COMPLETE**)
"""

from pyderasn import Any
from pyderasn import BitString
from pyderasn import Integer
from pyderasn import ObjectIdentifier
from pyderasn import Sequence
from pyderasn import SetOf
from pyderasn import tag_ctxc

from pygost.asn1schemas.x509 import AlgorithmIdentifier
from pygost.asn1schemas.x509 import Name
from pygost.asn1schemas.x509 import SubjectPublicKeyInfo


class AttributeValue(Any):
    pass


class AttributeValues(SetOf):
    schema = AttributeValue()


class Attribute(Sequence):
    schema = (
        ("type", ObjectIdentifier()),
        ("values", AttributeValues()),
    )


class Attributes(SetOf):
    schema = Attribute()


class CertificationRequestInfo(Sequence):
    schema = (
        ("version", Integer(0)),
        ("subject", Name()),
        ("subjectPKInfo", SubjectPublicKeyInfo()),
        ("attributes", Attributes(impl=tag_ctxc(0))),
    )


class CertificationRequest(Sequence):
    schema = (
        ("certificationRequestInfo", CertificationRequestInfo()),
        ("signatureAlgorithm", AlgorithmIdentifier()),
        ("signature", BitString()),
    )
