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
""":rfc:`5280` related structures (**NOT COMPLETE**)

They are taken from `PyDERASN <http://pyderasn.cypherpunks.ru/`__ tests.
"""

from pyderasn import Any
from pyderasn import BitString
from pyderasn import Boolean
from pyderasn import Choice
from pyderasn import GeneralizedTime
from pyderasn import Integer
from pyderasn import ObjectIdentifier
from pyderasn import OctetString
from pyderasn import PrintableString
from pyderasn import Sequence
from pyderasn import SequenceOf
from pyderasn import SetOf
from pyderasn import tag_ctxc
from pyderasn import tag_ctxp
from pyderasn import TeletexString
from pyderasn import UTCTime


class Version(Integer):
    schema = (
        ("v1", 0),
        ("v2", 1),
        ("v3", 2),
    )


class CertificateSerialNumber(Integer):
    pass


class AlgorithmIdentifier(Sequence):
    schema = (
        ("algorithm", ObjectIdentifier()),
        ("parameters", Any(optional=True)),
    )


class AttributeType(ObjectIdentifier):
    pass


class AttributeValue(Any):
    pass


class OrganizationName(Choice):
    schema = (
        ("printableString", PrintableString()),
        ("teletexString", TeletexString()),
    )


class AttributeTypeAndValue(Sequence):
    schema = (
        ("type", AttributeType(defines=(((".", "value"), {
            ObjectIdentifier("2.5.4.6"): PrintableString(),
            ObjectIdentifier("2.5.4.8"): PrintableString(),
            ObjectIdentifier("2.5.4.7"): PrintableString(),
            ObjectIdentifier("2.5.4.10"): OrganizationName(),
            ObjectIdentifier("2.5.4.3"): PrintableString(),
        }),))),
        ("value", AttributeValue()),
    )


class RelativeDistinguishedName(SetOf):
    schema = AttributeTypeAndValue()
    bounds = (1, float("+inf"))


class RDNSequence(SequenceOf):
    schema = RelativeDistinguishedName()


class Name(Choice):
    schema = (
        ("rdnSequence", RDNSequence()),
    )


class Time(Choice):
    schema = (
        ("utcTime", UTCTime()),
        ("generalTime", GeneralizedTime()),
    )


class Validity(Sequence):
    schema = (
        ("notBefore", Time()),
        ("notAfter", Time()),
    )


class SubjectPublicKeyInfo(Sequence):
    schema = (
        ("algorithm", AlgorithmIdentifier()),
        ("subjectPublicKey", BitString()),
    )


class UniqueIdentifier(BitString):
    pass


class Extension(Sequence):
    schema = (
        ("extnID", ObjectIdentifier()),
        ("critical", Boolean(default=False)),
        ("extnValue", OctetString()),
    )


class Extensions(SequenceOf):
    schema = Extension()
    bounds = (1, float("+inf"))


class TBSCertificate(Sequence):
    schema = (
        ("version", Version(expl=tag_ctxc(0), default="v1")),
        ("serialNumber", CertificateSerialNumber()),
        ("signature", AlgorithmIdentifier()),
        ("issuer", Name()),
        ("validity", Validity()),
        ("subject", Name()),
        ("subjectPublicKeyInfo", SubjectPublicKeyInfo()),
        ("issuerUniqueID", UniqueIdentifier(impl=tag_ctxp(1), optional=True)),
        ("subjectUniqueID", UniqueIdentifier(impl=tag_ctxp(2), optional=True)),
        ("extensions", Extensions(expl=tag_ctxc(3), optional=True)),
    )


class Certificate(Sequence):
    schema = (
        ("tbsCertificate", TBSCertificate()),
        ("signatureAlgorithm", AlgorithmIdentifier()),
        ("signatureValue", BitString()),
    )
