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
"""PKCS #12 related structures (**NOT COMPLETE**)
"""

from pyderasn import Any
from pyderasn import Choice
from pyderasn import Integer
from pyderasn import ObjectIdentifier
from pyderasn import OctetString
from pyderasn import Sequence
from pyderasn import SequenceOf
from pyderasn import SetOf
from pyderasn import tag_ctxc
from pyderasn import tag_ctxp

from pygost.asn1schemas.cms import CMSVersion
from pygost.asn1schemas.cms import ContentType
from pygost.asn1schemas.cms import Gost2814789Parameters
from pygost.asn1schemas.oids import id_data
from pygost.asn1schemas.oids import id_encryptedData
from pygost.asn1schemas.oids import id_Gost28147_89
from pygost.asn1schemas.oids import id_pbes2
from pygost.asn1schemas.oids import id_pbkdf2
from pygost.asn1schemas.x509 import AlgorithmIdentifier


class PBKDF2Salt(Choice):
    schema = (
        ("specified", OctetString()),
        # ("otherSource", PBKDF2SaltSources()),
    )


id_hmacWithSHA1 = ObjectIdentifier("1.2.840.113549.2.7")


class PBKDF2PRFs(AlgorithmIdentifier):
    schema = (
        ("algorithm", ObjectIdentifier(default=id_hmacWithSHA1)),
        ("parameters", Any(optional=True)),
    )


class IterationCount(Integer):
    bounds = (1, float("+inf"))


class KeyLength(Integer):
    bounds = (1, float("+inf"))


class PBKDF2Params(Sequence):
    schema = (
        ("salt", PBKDF2Salt()),
        ("iterationCount", IterationCount(optional=True)),
        ("keyLength", KeyLength(optional=True)),
        ("prf", PBKDF2PRFs()),
    )


class PBES2KDFs(AlgorithmIdentifier):
    schema = (
        ("algorithm", ObjectIdentifier(defines=(
            (("parameters",), {id_pbkdf2: PBKDF2Params()}),
        ))),
        ("parameters", Any(optional=True)),
    )


class PBES2Encs(AlgorithmIdentifier):
    schema = (
        ("algorithm", ObjectIdentifier(defines=(
            (("parameters",), {id_Gost28147_89: Gost2814789Parameters()}),
        ))),
        ("parameters", Any(optional=True)),
    )


class PBES2Params(Sequence):
    schema = (
        ("keyDerivationFunc", PBES2KDFs()),
        ("encryptionScheme", PBES2Encs()),
    )


class EncryptionAlgorithmIdentifier(AlgorithmIdentifier):
    schema = (
        ("algorithm", ObjectIdentifier(defines=(
            (("parameters",), {id_pbes2: PBES2Params()}),
        ))),
        ("parameters", Any(optional=True)),
    )


class ContentEncryptionAlgorithmIdentifier(EncryptionAlgorithmIdentifier):
    schema = (
        ("algorithm", ObjectIdentifier(defines=(
            (("parameters",), {id_pbes2: PBES2Params()}),
        ))),
        ("parameters", Any(optional=True)),
    )


class EncryptedContent(OctetString):
    pass


class EncryptedContentInfo(Sequence):
    schema = (
        ("contentType", ContentType()),
        ("contentEncryptionAlgorithm", ContentEncryptionAlgorithmIdentifier()),
        ("encryptedContent", EncryptedContent(impl=tag_ctxp(0), optional=True)),
    )


class EncryptedData(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("encryptedContentInfo", EncryptedContentInfo()),
        # ("unprotectedAttrs", UnprotectedAttributes(impl=tag_ctxc(1), optional=True)),
    )


class PKCS12BagSet(Any):
    pass


class AttrValue(SetOf):
    schema = Any()


class PKCS12Attribute(Sequence):
    schema = (
        ("attrId", ObjectIdentifier()),
        ("attrValue", AttrValue()),
    )


class PKCS12Attributes(SetOf):
    schema = PKCS12Attribute()


class SafeBag(Sequence):
    schema = (
        ("bagId", ObjectIdentifier(defines=(
            (("bagValue",), {id_encryptedData: EncryptedData()}),
        ))),
        ("bagValue", PKCS12BagSet(expl=tag_ctxc(0))),
        ("bagAttributes", PKCS12Attributes(optional=True)),
    )


class SafeContents(SequenceOf):
    schema = SafeBag()


OctetStringSafeContents = SafeContents(expl=OctetString.tag_default)


class AuthSafe(Sequence):
    schema = (
        ("contentType", ContentType(defines=(
            (("content",), {id_data: OctetStringSafeContents()}),
        ))),
        ("content", Any(expl=tag_ctxc(0))),
    )


class DigestInfo(Sequence):
    schema = (
        ("digestAlgorithm", AlgorithmIdentifier()),
        ("digest", OctetString()),
    )


class MacData(Sequence):
    schema = (
        ("mac", DigestInfo()),
        ("macSalt", OctetString()),
        ("iterations", Integer(default=1)),
    )


class PFX(Sequence):
    schema = (
        ("version", Integer(default=1)),
        ("authSafe", AuthSafe()),
        ("macData", MacData(optional=True)),
    )


class EncryptedPrivateKeyInfo(Sequence):
    schema = (
        ("encryptionAlgorithm", EncryptionAlgorithmIdentifier()),
        ("encryptedData", OctetString()),
    )


class PKCS8ShroudedKeyBag(EncryptedPrivateKeyInfo):
    pass
