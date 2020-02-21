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

from base64 import b64decode
from unittest import skipIf
from unittest import TestCase

from pygost.gost3410 import CURVES
from pygost.gost3410 import prv_unmarshal
from pygost.gost3410 import pub_marshal
from pygost.gost3410 import pub_unmarshal
from pygost.gost3410 import public_key
from pygost.gost3410 import verify
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.utils import hexdec

try:

    from pyderasn import Any
    from pyderasn import BitString
    from pyderasn import Boolean
    from pyderasn import GeneralizedTime
    from pyderasn import Integer
    from pyderasn import OctetString
    from pyderasn import PrintableString
    from pyderasn import UTCTime

    from pygost.asn1schemas.oids import id_at_commonName
    from pygost.asn1schemas.oids import id_ce_basicConstraints
    from pygost.asn1schemas.oids import id_GostR3410_2001_TestParamSet
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256_paramSetA
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512_paramSetTest
    from pygost.asn1schemas.oids import id_tc26_gost3411_2012_256
    from pygost.asn1schemas.oids import id_tc26_signwithdigest_gost3410_2012_256
    from pygost.asn1schemas.oids import id_tc26_signwithdigest_gost3410_2012_512
    from pygost.asn1schemas.pkcs10 import Attributes
    from pygost.asn1schemas.pkcs10 import CertificationRequest
    from pygost.asn1schemas.pkcs10 import CertificationRequestInfo
    from pygost.asn1schemas.x509 import AlgorithmIdentifier
    from pygost.asn1schemas.x509 import AttributeType
    from pygost.asn1schemas.x509 import AttributeTypeAndValue
    from pygost.asn1schemas.x509 import AttributeValue
    from pygost.asn1schemas.x509 import BasicConstraints
    from pygost.asn1schemas.x509 import Certificate
    from pygost.asn1schemas.x509 import CertificateList
    from pygost.asn1schemas.x509 import CertificateSerialNumber
    from pygost.asn1schemas.x509 import Extension
    from pygost.asn1schemas.x509 import Extensions
    from pygost.asn1schemas.x509 import GostR34102012PublicKeyParameters
    from pygost.asn1schemas.x509 import Name
    from pygost.asn1schemas.x509 import RDNSequence
    from pygost.asn1schemas.x509 import RelativeDistinguishedName
    from pygost.asn1schemas.x509 import SubjectPublicKeyInfo
    from pygost.asn1schemas.x509 import TBSCertificate
    from pygost.asn1schemas.x509 import TBSCertList
    from pygost.asn1schemas.x509 import Time
    from pygost.asn1schemas.x509 import Validity
    from pygost.asn1schemas.x509 import Version

except ImportError:
    pyderasn_exists = False
else:
    pyderasn_exists = True


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestCertificate(TestCase):
    """Certificate test vectors from "Использования алгоритмов ГОСТ Р
    34.10, ГОСТ Р 34.11 в профиле сертификата и списке отзыва
    сертификатов (CRL) инфраструктуры открытых ключей X.509"
    (TK26IOK.pdf)
    """

    def process_cert(self, curve_name, mode, hasher, prv_key_raw, cert_raw):
        cert, tail = Certificate().decode(cert_raw, ctx={
            "defines_by_path": (
                (
                    (
                        "tbsCertificate",
                        "subjectPublicKeyInfo",
                        "algorithm",
                        "algorithm",
                    ),
                    (
                        (
                            ("..", "subjectPublicKey"),
                            {
                                id_tc26_gost3410_2012_256: OctetString(),
                                id_tc26_gost3410_2012_512: OctetString(),
                            },
                        ),
                    ),
                ),
            ),
        })
        self.assertSequenceEqual(tail, b"")
        curve = CURVES[curve_name]
        prv_key = prv_unmarshal(prv_key_raw)
        spk = cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"]
        self.assertIsNotNone(spk.defined)
        _, pub_key_raw = spk.defined
        pub_key = pub_unmarshal(bytes(pub_key_raw), mode=mode)
        self.assertSequenceEqual(pub_key, public_key(curve, prv_key))
        self.assertTrue(verify(
            curve,
            pub_key,
            hasher(cert["tbsCertificate"].encode()).digest()[::-1],
            bytes(cert["signatureValue"]),
            mode=mode,
        ))

    def test_256(self):
        cert_raw = b64decode("""
MIICYjCCAg+gAwIBAgIBATAKBggqhQMHAQEDAjBWMSkwJwYJKoZIhvcNAQkBFhpH
b3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIw
MTIgKDI1NiBiaXQpIGV4YW1wbGUwHhcNMTMxMTA1MTQwMjM3WhcNMzAxMTAxMTQw
MjM3WjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNv
bTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgKDI1NiBiaXQpIGV4YW1wbGUwZjAf
BggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAut/Qw1MUq9KPqkdH
C2xAF3K7TugHfo9n525D2s5mFZdD5pwf90/i4vF0mFmr9nfRwMYP4o0Pg1mOn5Rl
aXNYraOBwDCBvTAdBgNVHQ4EFgQU1fIeN1HaPbw+XWUzbkJ+kHJUT0AwCwYDVR0P
BAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwfgYDVR0BBHcwdYAU1fIeN1HaPbw+XWUz
bkJ+kHJUT0ChWqRYMFYxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDEyQGV4
YW1wbGUuY29tMSkwJwYDVQQDEyBHb3N0UjM0MTAtMjAxMiAoMjU2IGJpdCkgZXhh
bXBsZYIBATAKBggqhQMHAQEDAgNBAF5bm4BbARR6hJLEoWJkOsYV3Hd7kXQQjz3C
dqQfmHrz6TI6Xojdh/t8ckODv/587NS5/6KsM77vc6Wh90NAT2s=
        """)
        prv_key_raw = hexdec("BFCF1D623E5CDD3032A7C6EABB4A923C46E43D640FFEAAF2C3ED39A8FA399924")[::-1]
        self.process_cert(
            "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
            2001,
            GOST34112012256,
            prv_key_raw,
            cert_raw,
        )

    def test_512(self):
        cert_raw = b64decode("""
MIIC6DCCAlSgAwIBAgIBATAKBggqhQMHAQEDAzBWMSkwJwYJKoZIhvcNAQkBFhpH
b3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIw
MTIgKDUxMiBiaXQpIGV4YW1wbGUwHhcNMTMxMDA0MDczNjA0WhcNMzAxMDAxMDcz
NjA0WjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNv
bTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgKDUxMiBiaXQpIGV4YW1wbGUwgaow
IQYIKoUDBwEBAQIwFQYJKoUDBwECAQICBggqhQMHAQECAwOBhAAEgYATGQ9VCiM5
FRGCQ8MEz2F1dANqhaEuywa8CbxOnTvaGJpFQVXQwkwvLFAKh7hk542vOEtxpKtT
CXfGf84nRhMH/Q9bZeAc2eO/yhxrsQhTBufa1Fuou2oe/jUOaG6RAtUUvRzhNTpp
RGGl1+EIY2vzzUua9j9Ol/gAoy/LNKQIfqOBwDCBvTAdBgNVHQ4EFgQUPcbTRXJZ
nHtjj+eBP7b5lcTMekIwCwYDVR0PBAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwfgYD
VR0BBHcwdYAUPcbTRXJZnHtjj+eBP7b5lcTMekKhWqRYMFYxKTAnBgkqhkiG9w0B
CQEWGkdvc3RSMzQxMC0yMDEyQGV4YW1wbGUuY29tMSkwJwYDVQQDEyBHb3N0UjM0
MTAtMjAxMiAoNTEyIGJpdCkgZXhhbXBsZYIBATAKBggqhQMHAQEDAwOBgQBObS7o
ppPTXzHyVR1DtPa8b57nudJzI4czhsfeX5HDntOq45t9B/qSs8dC6eGxbhHZ9zCO
SFtxWYdmg0au8XI9Xb8vTC1qdwWID7FFjMWDNQZb6lYh/J+8F2xKylvB5nIlRZqO
o3eUNFkNyHJwQCk2WoOlO16zwGk2tdKH4KmD5w==
        """)
        prv_key_raw = hexdec("3FC01CDCD4EC5F972EB482774C41E66DB7F380528DFE9E67992BA05AEE462435757530E641077CE587B976C8EEB48C48FD33FD175F0C7DE6A44E014E6BCB074B")[::-1]
        self.process_cert(
            "id-tc26-gost-3410-12-512-paramSetB",
            2012,
            GOST34112012512,
            prv_key_raw,
            cert_raw,
        )


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestRFC4491bis(TestCase):
    """Test vectors from https://tools.ietf.org/html/draft-deremin-rfc4491-bis-02
    """

    def _test_vector(
            self,
            curve_name,
            mode,
            hsh,
            ai_spki,
            ai_sign,
            cert_serial,
            prv_hex,
            cr_sign_hex,
            cr_b64,
            c_sign_hex,
            c_b64,
            crl_sign_hex,
            crl_b64,
    ):
        prv_raw = hexdec(prv_hex)[::-1]
        prv = prv_unmarshal(prv_raw)
        curve = CURVES[curve_name]
        pub = public_key(curve, prv)
        pub_raw = pub_marshal(pub, mode=mode)
        subj = Name(("rdnSequence", RDNSequence([
            RelativeDistinguishedName((
                AttributeTypeAndValue((
                    ("type", AttributeType(id_at_commonName)),
                    ("value", AttributeValue(PrintableString("Example"))),
                )),
            ))
        ])))
        spki = SubjectPublicKeyInfo((
            ("algorithm", ai_spki),
            ("subjectPublicKey", BitString(OctetString(pub_raw).encode())),
        ))

        # Certification request
        cri = CertificationRequestInfo((
            ("version", Integer(0)),
            ("subject", subj),
            ("subjectPKInfo", spki),
            ("attributes", Attributes()),
        ))
        sign = hexdec(cr_sign_hex)
        self.assertTrue(verify(
            curve,
            pub,
            hsh(cri.encode()).digest()[::-1],
            sign,
            mode=mode,
        ))
        cr = CertificationRequest((
            ("certificationRequestInfo", cri),
            ("signatureAlgorithm", ai_sign),
            ("signature", BitString(sign)),
        ))
        self.assertSequenceEqual(cr.encode(), b64decode(cr_b64))

        # Certificate
        tbs = TBSCertificate((
            ("version", Version("v3")),
            ("serialNumber", CertificateSerialNumber(cert_serial)),
            ("signature", ai_sign),
            ("issuer", subj),
            ("validity", Validity((
                ("notBefore", Time(("utcTime", UTCTime(b"010101000000Z")))),
                ("notAfter", Time(("generalTime", GeneralizedTime(b"20501231000000Z")))),
            ))),
            ("subject", subj),
            ("subjectPublicKeyInfo", spki),
            ("extensions", Extensions((
                Extension((
                    ("extnID", id_ce_basicConstraints),
                    ("critical", Boolean(True)),
                    ("extnValue", OctetString(
                        BasicConstraints((("cA", Boolean(True)),)).encode()
                    )),
                )),
            ))),
        ))
        sign = hexdec(c_sign_hex)
        self.assertTrue(verify(
            curve,
            pub,
            hsh(tbs.encode()).digest()[::-1],
            sign,
            mode=mode,
        ))
        cert = Certificate((
            ("tbsCertificate", tbs),
            ("signatureAlgorithm", ai_sign),
            ("signatureValue", BitString(sign)),
        ))
        self.assertSequenceEqual(cert.encode(), b64decode(c_b64))

        # CRL
        tbs = TBSCertList((
            ("version", Version("v2")),
            ("signature", ai_sign),
            ("issuer", subj),
            ("thisUpdate", Time(("utcTime", UTCTime(b"140101000000Z")))),
            ("nextUpdate", Time(("utcTime", UTCTime(b"140102000000Z")))),
        ))
        sign = hexdec(crl_sign_hex)
        self.assertTrue(verify(
            curve,
            pub,
            hsh(tbs.encode()).digest()[::-1],
            sign,
            mode=mode,
        ))
        crl = CertificateList((
            ("tbsCertList", tbs),
            ("signatureAlgorithm", ai_sign),
            ("signatureValue", BitString(sign)),
        ))
        self.assertSequenceEqual(crl.encode(), b64decode(crl_b64))

    def test_256_test_paramset(self):
        self._test_vector(
            "id-GostR3410-2001-TestParamSet",
            2001,
            GOST34112012256,
            AlgorithmIdentifier((
                ("algorithm", id_tc26_gost3410_2012_256),
                ("parameters", Any(
                    GostR34102012PublicKeyParameters((
                        ("publicKeyParamSet", id_GostR3410_2001_TestParamSet),
                        ("digestParamSet", id_tc26_gost3411_2012_256),
                    ))
                )),
            )),
            AlgorithmIdentifier((
                ("algorithm", id_tc26_signwithdigest_gost3410_2012_256),
            )),
            10,
            "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28",
            "6AAAB38E35D4AAA517940301799122D855484F579F4CBB96D63CDFDF3ACC432A41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493",
            """
MIHTMIGBAgEAMBIxEDAOBgNVBAMTB0V4YW1wbGUwZjAfBggqhQMHAQEBATATBgcq
hQMCAiMABggqhQMHAQECAgNDAARAC9hv5djbiWaPeJtOHbqFhcVQi0XsW1nYkG3b
cOJJK3/ad/+HGhD73ydm0pPF0WSvuzx7lzpByIXRHXDWibTxJqAAMAoGCCqFAwcB
AQMCA0EAaqqzjjXUqqUXlAMBeZEi2FVIT1efTLuW1jzf3zrMQypBqijS8asUgoDN
ntVv7aQZdAU1VKQnZ7g60EP9OdwEkw==
            """,
            "4D53F012FE081776507D4D9BB81F00EFDB4EEFD4AB83BAC4BACF735173CFA81C41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493",
            """
MIIBLTCB26ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw
IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4
YW1wbGUwZjAfBggqhQMHAQEBATATBgcqhQMCAiMABggqhQMHAQECAgNDAARAC9hv
5djbiWaPeJtOHbqFhcVQi0XsW1nYkG3bcOJJK3/ad/+HGhD73ydm0pPF0WSvuzx7
lzpByIXRHXDWibTxJqMTMBEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhQMHAQEDAgNB
AE1T8BL+CBd2UH1Nm7gfAO/bTu/Uq4O6xLrPc1Fzz6gcQaoo0vGrFIKAzZ7Vb+2k
GXQFNVSkJ2e4OtBD/TncBJM=
            """,
            "42BF392A14D3EBE957AF3E46CB50BF5F4221A003AD3D172753C94A9C37A31D2041AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493",
            """
MIGSMEECAQEwCgYIKoUDBwEBAwIwEjEQMA4GA1UEAxMHRXhhbXBsZRcNMTQwMTAx
MDAwMDAwWhcNMTQwMTAyMDAwMDAwWjAKBggqhQMHAQEDAgNBAEK/OSoU0+vpV68+
RstQv19CIaADrT0XJ1PJSpw3ox0gQaoo0vGrFIKAzZ7Vb+2kGXQFNVSkJ2e4OtBD
/TncBJM=
            """,
        )

    def test_256a_paramset(self):
        self._test_vector(
            "id-tc26-gost-3410-2012-256-paramSetA",
            2001,
            GOST34112012256,
            AlgorithmIdentifier((
                ("algorithm", id_tc26_gost3410_2012_256),
                ("parameters", Any(
                    GostR34102012PublicKeyParameters((
                        ("publicKeyParamSet", id_tc26_gost3410_2012_256_paramSetA),
                    ))
                )),
            )),
            AlgorithmIdentifier((
                ("algorithm", id_tc26_signwithdigest_gost3410_2012_256),
            )),
            10,
            "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28",
            "1BDC2A1317679B66232F63EA16FF7C64CCAAB9AD855FC6E18091661DB79D48121D0E1DA5BE347C6F1B5256C7AEAC200AD64AC77A6F5B3A0E097318E7AE6EE769",
            """
MIHKMHkCAQAwEjEQMA4GA1UEAxMHRXhhbXBsZTBeMBcGCCqFAwcBAQEBMAsGCSqF
AwcBAgEBAQNDAARAdCeV1L7ohN3yhQ/sA+o/rxhE4B2dpgtkUJOlXibfw5l49ZbP
TU0MbPHRiUPZRJPRa57AoW1RLS4SfMRpGmMY4qAAMAoGCCqFAwcBAQMCA0EAG9wq
Exdnm2YjL2PqFv98ZMyqua2FX8bhgJFmHbedSBIdDh2lvjR8bxtSVseurCAK1krH
em9bOg4Jcxjnrm7naQ==
            """,
            "140B4DA9124B09CB0D5CE928EE874273A310129492EC0E29369E3B791248578C1D0E1DA5BE347C6F1B5256C7AEAC200AD64AC77A6F5B3A0E097318E7AE6EE769",
            """
MIIBJTCB06ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw
IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4
YW1wbGUwXjAXBggqhQMHAQEBATALBgkqhQMHAQIBAQEDQwAEQHQnldS+6ITd8oUP
7APqP68YROAdnaYLZFCTpV4m38OZePWWz01NDGzx0YlD2UST0WuewKFtUS0uEnzE
aRpjGOKjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoUDBwEBAwIDQQAUC02pEksJ
yw1c6Sjuh0JzoxASlJLsDik2njt5EkhXjB0OHaW+NHxvG1JWx66sIArWSsd6b1s6
DglzGOeubudp
            """,
            "14BD68087C3B903C7AA28B07FEB2E7BD6FE0963F563267359F5CD8EAB45059AD1D0E1DA5BE347C6F1B5256C7AEAC200AD64AC77A6F5B3A0E097318E7AE6EE769",
            """
MIGSMEECAQEwCgYIKoUDBwEBAwIwEjEQMA4GA1UEAxMHRXhhbXBsZRcNMTQwMTAx
MDAwMDAwWhcNMTQwMTAyMDAwMDAwWjAKBggqhQMHAQEDAgNBABS9aAh8O5A8eqKL
B/6y571v4JY/VjJnNZ9c2Oq0UFmtHQ4dpb40fG8bUlbHrqwgCtZKx3pvWzoOCXMY
565u52k=
            """,
        )

    def test_512_test_paramset(self):
        self._test_vector(
            "id-tc26-gost-3410-2012-512-paramSetTest",
            2012,
            GOST34112012512,
            AlgorithmIdentifier((
                ("algorithm", id_tc26_gost3410_2012_512),
                ("parameters", Any(
                    GostR34102012PublicKeyParameters((
                        ("publicKeyParamSet", id_tc26_gost3410_2012_512_paramSetTest),
                    ))
                )),
            )),
            AlgorithmIdentifier((
                ("algorithm", id_tc26_signwithdigest_gost3410_2012_512),
            )),
            11,
            "0BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4",
            "433B1D6CE40A51F1E5737EB16AA2C683829A405B9D9127E21260FC9D6AC05D87BF24E26C45278A5C2192A75BA94993ABD6074E7FF1BF03FD2F5397AFA1D945582F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36",
            """
MIIBTzCBvAIBADASMRAwDgYDVQQDEwdFeGFtcGxlMIGgMBcGCCqFAwcBAQECMAsG
CSqFAwcBAgECAAOBhAAEgYDh7zDVLGEz3dmdHVxBRVz3302LTJJbvGmvFDPRVlhR
Wt0hRoUMMlxbgcEzvmVaqMTUQOe5io1ZSHsMdpa8xV0R7L53NqnsNX/y/TmTH04R
TLjNo1knCsfw5/9D2UGUGeph/Sq3f12fY1I9O1CgT2PioM9Rt8E63CFWDwvUDMnH
N6AAMAoGCCqFAwcBAQMDA4GBAEM7HWzkClHx5XN+sWqixoOCmkBbnZEn4hJg/J1q
wF2HvyTibEUnilwhkqdbqUmTq9YHTn/xvwP9L1OXr6HZRVgvhvpgoIEJGiPdeV4e
PGie5RKjyC7g3MJkPHjuqPys01SSVYSGsg8cnsGXyQaZhQJgyTvLzZxcMxfhk0Th
c642
            """,
            "415703D892F1A5F3F68C4353189A7EE207B80B5631EF9D49529A4D6B542C2CFA15AA2EACF11F470FDE7D954856903C35FD8F955EF300D95C77534A724A0EEE702F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36",
            """
MIIBqjCCARagAwIBAgIBCzAKBggqhQMHAQEDAzASMRAwDgYDVQQDEwdFeGFtcGxl
MCAXDTAxMDEwMTAwMDAwMFoYDzIwNTAxMjMxMDAwMDAwWjASMRAwDgYDVQQDEwdF
eGFtcGxlMIGgMBcGCCqFAwcBAQECMAsGCSqFAwcBAgECAAOBhAAEgYDh7zDVLGEz
3dmdHVxBRVz3302LTJJbvGmvFDPRVlhRWt0hRoUMMlxbgcEzvmVaqMTUQOe5io1Z
SHsMdpa8xV0R7L53NqnsNX/y/TmTH04RTLjNo1knCsfw5/9D2UGUGeph/Sq3f12f
Y1I9O1CgT2PioM9Rt8E63CFWDwvUDMnHN6MTMBEwDwYDVR0TAQH/BAUwAwEB/zAK
BggqhQMHAQEDAwOBgQBBVwPYkvGl8/aMQ1MYmn7iB7gLVjHvnUlSmk1rVCws+hWq
LqzxH0cP3n2VSFaQPDX9j5Ve8wDZXHdTSnJKDu5wL4b6YKCBCRoj3XleHjxonuUS
o8gu4NzCZDx47qj8rNNUklWEhrIPHJ7Bl8kGmYUCYMk7y82cXDMX4ZNE4XOuNg==
            """,
            "3A13FB7AECDB5560EEF6137CFC5DD64691732EBFB3690A1FC0C7E8A4EEEA08307D648D4DC0986C46A87B3FBE4C7AF42EA34359C795954CA39FF3ABBED9051F4D2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36",
            """
MIHTMEECAQEwCgYIKoUDBwEBAwMwEjEQMA4GA1UEAxMHRXhhbXBsZRcNMTQwMTAx
MDAwMDAwWhcNMTQwMTAyMDAwMDAwWjAKBggqhQMHAQEDAwOBgQA6E/t67NtVYO72
E3z8XdZGkXMuv7NpCh/Ax+ik7uoIMH1kjU3AmGxGqHs/vkx69C6jQ1nHlZVMo5/z
q77ZBR9NL4b6YKCBCRoj3XleHjxonuUSo8gu4NzCZDx47qj8rNNUklWEhrIPHJ7B
l8kGmYUCYMk7y82cXDMX4ZNE4XOuNg==
            """,
        )
