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
"""CMS related structures (**NOT COMPLETE**)
"""

from pyderasn import Any
from pyderasn import BitString
from pyderasn import Choice
from pyderasn import Integer
from pyderasn import ObjectIdentifier
from pyderasn import OctetString
from pyderasn import Sequence
from pyderasn import SequenceOf
from pyderasn import SetOf
from pyderasn import tag_ctxc
from pyderasn import tag_ctxp

from pygost.asn1schemas.oids import id_digestedData
from pygost.asn1schemas.oids import id_envelopedData
from pygost.asn1schemas.oids import id_Gost28147_89
from pygost.asn1schemas.oids import id_signedData
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512
from pygost.asn1schemas.x509 import AlgorithmIdentifier
from pygost.asn1schemas.x509 import Certificate
from pygost.asn1schemas.x509 import SubjectPublicKeyInfo


class CMSVersion(Integer):
    pass


class ContentType(ObjectIdentifier):
    pass


class RecipientIdentifier(Choice):
    schema = (
        ("issuerAndSerialNumber", Any()),
        # ("subjectKeyIdentifier", SubjectKeyIdentifier(impl=tag_ctxp(0))),
    )


class Gost2814789Key(OctetString):
    bounds = (32, 32)


class Gost2814789MAC(OctetString):
    bounds = (4, 4)


class Gost2814789EncryptedKey(Sequence):
    schema = (
        ("encryptedKey", Gost2814789Key()),
        ("maskKey", Gost2814789Key(impl=tag_ctxp(0), optional=True)),
        ("macKey", Gost2814789MAC()),
    )


class GostR34102001TransportParameters(Sequence):
    schema = (
        ("encryptionParamSet", ObjectIdentifier()),
        ("ephemeralPublicKey", SubjectPublicKeyInfo(
            impl=tag_ctxc(0),
            optional=True,
        )),
        ("ukm", OctetString()),
    )


class GostR3410KeyTransport(Sequence):
    schema = (
        ("sessionEncryptedKey", Gost2814789EncryptedKey()),
        ("transportParameters", GostR34102001TransportParameters(
            impl=tag_ctxc(0),
            optional=True,
        )),
    )


class KeyEncryptionAlgorithmIdentifier(AlgorithmIdentifier):
    schema = (
        ("algorithm", ObjectIdentifier(defines=(
            (("..", "encryptedKey"), {
                id_tc26_gost3410_2012_256: GostR3410KeyTransport(),
                id_tc26_gost3410_2012_512: GostR3410KeyTransport(),
            }),
            (("..", "recipientEncryptedKeys", any, "encryptedKey"), {
                id_tc26_gost3410_2012_256: Gost2814789EncryptedKey(),
                id_tc26_gost3410_2012_512: Gost2814789EncryptedKey(),
            }),
        ))),
        ("parameters", Any(optional=True)),
    )


class EncryptedKey(OctetString):
    pass


class KeyTransRecipientInfo(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("rid", RecipientIdentifier()),
        ("keyEncryptionAlgorithm", KeyEncryptionAlgorithmIdentifier()),
        ("encryptedKey", EncryptedKey()),
    )


class OriginatorPublicKey(Sequence):
    schema = (
        ("algorithm", AlgorithmIdentifier()),
        ("publicKey", BitString()),
    )


class OriginatorIdentifierOrKey(Choice):
    schema = (
        # ("issuerAndSerialNumber", IssuerAndSerialNumber()),
        # ("subjectKeyIdentifier", SubjectKeyIdentifier(impl=tag_ctxp(0))),
        ("originatorKey", OriginatorPublicKey(impl=tag_ctxc(1))),
    )


class UserKeyingMaterial(OctetString):
    pass


class KeyAgreeRecipientIdentifier(Choice):
    schema = (
        ("issuerAndSerialNumber", Any()),
        # ("rKeyId", RecipientKeyIdentifier(impl=tag_ctxc(0))),
    )


class RecipientEncryptedKey(Sequence):
    schema = (
        ("rid", KeyAgreeRecipientIdentifier()),
        ("encryptedKey", EncryptedKey()),
    )


class RecipientEncryptedKeys(SequenceOf):
    schema = RecipientEncryptedKey()


class KeyAgreeRecipientInfo(Sequence):
    schema = (
        ("version", CMSVersion(3)),
        ("originator", OriginatorIdentifierOrKey(expl=tag_ctxc(0))),
        ("ukm", UserKeyingMaterial(expl=tag_ctxc(1), optional=True)),
        ("keyEncryptionAlgorithm", KeyEncryptionAlgorithmIdentifier()),
        ("recipientEncryptedKeys", RecipientEncryptedKeys()),
    )


class RecipientInfo(Choice):
    schema = (
        ("ktri", KeyTransRecipientInfo()),
        ("kari", KeyAgreeRecipientInfo(impl=tag_ctxc(1))),
        # ("kekri", KEKRecipientInfo(impl=tag_ctxc(2))),
        # ("pwri", PasswordRecipientInfo(impl=tag_ctxc(3))),
        # ("ori", OtherRecipientInfo(impl=tag_ctxc(4))),
    )


class RecipientInfos(SetOf):
    schema = RecipientInfo()
    bounds = (1, float("+inf"))


class Gost2814789IV(OctetString):
    bounds = (8, 8)


class Gost2814789Parameters(Sequence):
    schema = (
        ("iv", Gost2814789IV()),
        ("encryptionParamSet", ObjectIdentifier()),
    )


class ContentEncryptionAlgorithmIdentifier(AlgorithmIdentifier):
    schema = (
        ("algorithm", ObjectIdentifier(defines=(
            (("parameters",), {id_Gost28147_89: Gost2814789Parameters()}),
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


class EnvelopedData(Sequence):
    schema = (
        ("version", CMSVersion()),
        # ("originatorInfo", OriginatorInfo(impl=tag_ctxc(0), optional=True)),
        ("recipientInfos", RecipientInfos()),
        ("encryptedContentInfo", EncryptedContentInfo()),
        # ("unprotectedAttrs", UnprotectedAttributes(impl=tag_ctxc(1), optional=True)),
    )


class EncapsulatedContentInfo(Sequence):
    schema = (
        ("eContentType", ContentType()),
        ("eContent", OctetString(expl=tag_ctxc(0), optional=True)),
    )


class SignerIdentifier(Choice):
    schema = (
        ("issuerAndSerialNumber", Any()),
        # ("subjectKeyIdentifier", SubjectKeyIdentifier(impl=tag_ctxp(0))),
    )


class DigestAlgorithmIdentifiers(SetOf):
    schema = AlgorithmIdentifier()


class DigestAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class SignatureAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class SignatureValue(OctetString):
    pass


class SignerInfo(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("sid", SignerIdentifier()),
        ("digestAlgorithm", DigestAlgorithmIdentifier()),
        # ("signedAttrs", SignedAttributes(impl=tag_ctxc(0), optional=True)),
        ("signatureAlgorithm", SignatureAlgorithmIdentifier()),
        ("signature", SignatureValue()),
        # ("unsignedAttrs", UnsignedAttributes(impl=tag_ctxc(1), optional=True)),
    )


class SignerInfos(SetOf):
    schema = SignerInfo()


class CertificateChoices(Choice):
    schema = (
        ('certificate', Certificate()),
        # ('extendedCertificate', ExtendedCertificate(impl=tag_ctxp(0))),
        # ('v1AttrCert', AttributeCertificateV1(impl=tag_ctxc(1))),  # V1 is osbolete
        # ('v2AttrCert', AttributeCertificateV2(impl=tag_ctxc(2))),
        # ('other', OtherCertificateFormat(impl=tag_ctxc(3))),
    )


class CertificateSet(SetOf):
    schema = CertificateChoices()


class SignedData(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("digestAlgorithms", DigestAlgorithmIdentifiers()),
        ("encapContentInfo", EncapsulatedContentInfo()),
        ("certificates", CertificateSet(impl=tag_ctxc(0), optional=True)),
        # ("crls", RevocationInfoChoices(impl=tag_ctxc(1), optional=True)),
        ("signerInfos", SignerInfos()),
    )


class Digest(OctetString):
    pass


class DigestedData(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("digestAlgorithm", DigestAlgorithmIdentifier()),
        ("encapContentInfo", EncapsulatedContentInfo()),
        ("digest", Digest()),
    )


class ContentInfo(Sequence):
    schema = (
        ("contentType", ContentType(defines=(
            (("content",), {
                id_digestedData: DigestedData(),
                id_envelopedData: EnvelopedData(),
                id_signedData: SignedData(),
            }),
        ))),
        ("content", Any(expl=tag_ctxc(0))),
    )
