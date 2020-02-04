"""Create example self-signed X.509 certificate
"""

from base64 import standard_b64encode
from datetime import datetime
from datetime import timedelta
from os import urandom
from sys import argv
from sys import exit as sys_exit
from textwrap import fill

from pyderasn import Any
from pyderasn import BitString
from pyderasn import Integer
from pyderasn import OctetString
from pyderasn import PrintableString
from pyderasn import UTCTime

from pygost.asn1schemas.oids import id_at_commonName
from pygost.asn1schemas.oids import id_ce_subjectKeyIdentifier
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512_paramSetA
from pygost.asn1schemas.oids import id_tc26_gost3411_2012_512
from pygost.asn1schemas.oids import id_tc26_signwithdigest_gost3410_2012_512
from pygost.asn1schemas.prvkey import PrivateKey
from pygost.asn1schemas.prvkey import PrivateKeyAlgorithmIdentifier
from pygost.asn1schemas.prvkey import PrivateKeyInfo
from pygost.asn1schemas.x509 import AlgorithmIdentifier
from pygost.asn1schemas.x509 import AttributeType
from pygost.asn1schemas.x509 import AttributeTypeAndValue
from pygost.asn1schemas.x509 import AttributeValue
from pygost.asn1schemas.x509 import Certificate
from pygost.asn1schemas.x509 import CertificateSerialNumber
from pygost.asn1schemas.x509 import Extension
from pygost.asn1schemas.x509 import Extensions
from pygost.asn1schemas.x509 import GostR34102012PublicKeyParameters
from pygost.asn1schemas.x509 import Name
from pygost.asn1schemas.x509 import RDNSequence
from pygost.asn1schemas.x509 import RelativeDistinguishedName
from pygost.asn1schemas.x509 import SubjectKeyIdentifier
from pygost.asn1schemas.x509 import SubjectPublicKeyInfo
from pygost.asn1schemas.x509 import TBSCertificate
from pygost.asn1schemas.x509 import Time
from pygost.asn1schemas.x509 import Validity
from pygost.asn1schemas.x509 import Version
from pygost.gost3410 import CURVES
from pygost.gost3410 import prv_unmarshal
from pygost.gost3410 import pub_marshal
from pygost.gost3410 import public_key
from pygost.gost3410 import sign
from pygost.gost34112012512 import GOST34112012512

if len(argv) != 2:
    sys_exit("Usage: cert-selfsigned-example.py COMMON-NAME")


def pem(obj):
    return fill(standard_b64encode(obj.encode()).decode('ascii'), 64)


key_params = GostR34102012PublicKeyParameters((
    ("publicKeyParamSet", id_tc26_gost3410_2012_512_paramSetA),
    ("digestParamSet", id_tc26_gost3411_2012_512),
))

prv_raw = urandom(64)
print("-----BEGIN PRIVATE KEY-----")
print(pem(PrivateKeyInfo((
    ("version", Integer(0)),
    ("privateKeyAlgorithm", PrivateKeyAlgorithmIdentifier((
        ("algorithm", id_tc26_gost3410_2012_512),
        ("parameters", Any(key_params)),
    ))),
    ("privateKey", PrivateKey(prv_raw)),
))))
print("-----END PRIVATE KEY-----")

prv = prv_unmarshal(prv_raw)
curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]
pub_raw = pub_marshal(public_key(curve, prv), mode=2012)
subj = Name(("rdnSequence", RDNSequence([
    RelativeDistinguishedName((
        AttributeTypeAndValue((
            ("type", AttributeType(id_at_commonName)),
            ("value", AttributeValue(PrintableString(argv[1]))),
        )),
    ))
])))
not_before = datetime.utcnow()
not_after = not_before + timedelta(days=365)
ai_sign = AlgorithmIdentifier((
    ("algorithm", id_tc26_signwithdigest_gost3410_2012_512),
))
tbs = TBSCertificate((
    ("version", Version("v3")),
    ("serialNumber", CertificateSerialNumber(12345)),
    ("signature", ai_sign),
    ("issuer", subj),
    ("validity", Validity((
        ("notBefore", Time(("utcTime", UTCTime(not_before)))),
        ("notAfter", Time(("utcTime", UTCTime(not_after)))),
    ))),
    ("subject", subj),
    ("subjectPublicKeyInfo", SubjectPublicKeyInfo((
        ("algorithm", AlgorithmIdentifier((
            ("algorithm", id_tc26_gost3410_2012_512),
            ("parameters", Any(key_params)),
        ))),
        ("subjectPublicKey", BitString(OctetString(pub_raw).encode())),
    ))),
    ("extensions", Extensions((
        Extension((
            ("extnID", id_ce_subjectKeyIdentifier),
            ("extnValue", OctetString(
                SubjectKeyIdentifier(GOST34112012512(pub_raw).digest()[:20]).encode()
            )),
        )),
    ))),
))
cert = Certificate((
    ("tbsCertificate", tbs),
    ("signatureAlgorithm", ai_sign),
    ("signatureValue", BitString(sign(
        curve,
        prv,
        GOST34112012512(tbs.encode()).digest(),
        mode=2012,
    ))),
))
print("-----BEGIN CERTIFICATE-----")
print(pem(cert))
print("-----END CERTIFICATE-----")
