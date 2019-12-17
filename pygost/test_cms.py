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

from pygost.gost28147 import cfb_decrypt
from pygost.gost3410 import CURVES
from pygost.gost3410 import prv_unmarshal
from pygost.gost3410 import pub_unmarshal
from pygost.gost3410 import public_key
from pygost.gost3410 import verify
from pygost.gost3410_vko import kek_34102012256
from pygost.gost3410_vko import ukm_unmarshal
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.utils import hexdec
from pygost.wrap import unwrap_cryptopro
from pygost.wrap import unwrap_gost

try:
    from pyderasn import DecodePathDefBy
    from pyderasn import OctetString

    from pygost.asn1schemas.cms import ContentInfo
    from pygost.asn1schemas.oids import id_envelopedData
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512
except ImportError:
    pyderasn_exists = False
else:
    pyderasn_exists = True


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestSigned(TestCase):
    """SignedData test vectors from "Использование
    алгоритмов ГОСТ 28147-89, ГОСТ Р 34.11 и ГОСТ Р 34.10 в
    криптографических сообщениях формата CMS" (TK26CMS.pdf)
    """

    def process_cms(
            self,
            content_info_raw,
            prv_key_raw,
            curve_name,
            hasher,
            mode,
    ):
        content_info, tail = ContentInfo().decode(content_info_raw)
        self.assertSequenceEqual(tail, b"")
        self.assertIsNotNone(content_info["content"].defined)
        _, signed_data = content_info["content"].defined
        self.assertEqual(len(signed_data["signerInfos"]), 1)
        curve = CURVES[curve_name]
        self.assertTrue(verify(
            curve,
            public_key(curve, prv_unmarshal(prv_key_raw)),
            hasher(bytes(signed_data["encapContentInfo"]["eContent"])).digest()[::-1],
            bytes(signed_data["signerInfos"][0]["signature"]),
            mode=mode,
        ))

    def test_256(self):
        content_info_raw = b64decode("""
MIIBBQYJKoZIhvcNAQcCoIH3MIH0AgEBMQ4wDAYIKoUDBwEBAgIFADAbBgkqhkiG
9w0BBwGgDgQMVGVzdCBtZXNzYWdlMYHBMIG+AgEBMFswVjEpMCcGCSqGSIb3DQEJ
ARYaR29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RSMzQx
MC0yMDEyICgyNTYgYml0KSBleGFtcGxlAgEBMAwGCCqFAwcBAQICBQAwDAYIKoUD
BwEBAQEFAARAkptb2ekZbC94FaGDQeP70ExvTkXtOY9zgz3cCco/hxPhXUVo3eCx
VNwDQ8enFItJZ8DEX4blZ8QtziNCMl5HbA==
        """)
        prv_key_raw = hexdec("BFCF1D623E5CDD3032A7C6EABB4A923C46E43D640FFEAAF2C3ED39A8FA399924")[::-1]
        self.process_cms(
            content_info_raw,
            prv_key_raw,
            "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
            GOST34112012256,
            2001,
        )

    def test_512(self):
        content_info_raw = b64decode("""
MIIBSQYJKoZIhvcNAQcCoIIBOjCCATYCAQExDjAMBggqhQMHAQECAwUAMBsGCSqG
SIb3DQEHAaAOBAxUZXN0IG1lc3NhZ2UxggECMIH/AgEBMFswVjEpMCcGCSqGSIb3
DQEJARYaR29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RS
MzQxMC0yMDEyICg1MTIgYml0KSBleGFtcGxlAgEBMAwGCCqFAwcBAQIDBQAwDAYI
KoUDBwEBAQIFAASBgFyVohNhMHUi/+RAF3Gh/cC7why6v+4jPWVlx1TYlXtV8Hje
hI2Y+rP52/LO6EUHG/XcwCBbUxmRWsbUSRRBAexmaafkSdvv2FFwC8kHOcti+UPX
PS+KRYxT8vhcsBLWWxDkc1McI7aF09hqtED36mQOfACzeJjEoUjALpmJob1V
        """)
        prv_key_raw = hexdec("3FC01CDCD4EC5F972EB482774C41E66DB7F380528DFE9E67992BA05AEE462435757530E641077CE587B976C8EEB48C48FD33FD175F0C7DE6A44E014E6BCB074B")[::-1]
        self.process_cms(
            content_info_raw,
            prv_key_raw,
            "id-tc26-gost-3410-12-512-paramSetB",
            GOST34112012512,
            2012,
        )


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestDigested(TestCase):
    """DigestedData test vectors from "Использование
    алгоритмов ГОСТ 28147-89, ГОСТ Р 34.11 и ГОСТ Р 34.10 в
    криптографических сообщениях формата CMS" (TK26CMS.pdf)
    """

    def process_cms(self, content_info_raw, hasher):
        content_info, tail = ContentInfo().decode(content_info_raw)
        self.assertSequenceEqual(tail, b"")
        self.assertIsNotNone(content_info["content"].defined)
        _, digested_data = content_info["content"].defined
        self.assertSequenceEqual(
            hasher(bytes(digested_data["encapContentInfo"]["eContent"])).digest(),
            bytes(digested_data["digest"]),
        )

    def test_256(self):
        content_info_raw = b64decode("""
MIGdBgkqhkiG9w0BBwWggY8wgYwCAQAwDAYIKoUDBwEBAgIFADBXBgkqhkiG9w0B
BwGgSgRI0eUg4uXy8OgsINHy8Ojh7uboIOLt8/boLCDi5f7y+iDxIOzu8P8g8fLw
5evg7Ogg7eAg9fDg4fD7/yDv6/rq+yDI4+7w5eL7BCCd0v5OkECeXah/U5dtdAWw
wMrGKPxmmnQdUAY8VX6PUA==
        """)
        self.process_cms(content_info_raw, GOST34112012256)

    def test_512(self):
        content_info_raw = b64decode("""
MIG0BgkqhkiG9w0BBwWggaYwgaMCAQAwDAYIKoUDBwEBAgMFADBOBgkqhkiG9w0B
BwGgQQQ/MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx
MjM0NTY3ODkwMTIzNDU2Nzg5MDEyBEAbVNAaSvW51cw9htaNKFRisZq8JHUiLzXA
hRIr5Lof+gCtMPh2ezqCOExldPAkwxHipIEzKwjvf0F5eJHBZG9I
        """)
        self.process_cms(content_info_raw, GOST34112012512)


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestEnvelopedKTRI(TestCase):
    """EnvelopedData KeyTransRecipientInfo-based test vectors from
    "Использование алгоритмов ГОСТ 28147-89, ГОСТ Р 34.11 и ГОСТ Р 34.10
    в криптографических сообщениях формата CMS" (TK26CMS.pdf)
    """

    def process_cms(
            self,
            content_info_raw,
            prv_key_our,
            curve_name,
            keker,
            plaintext_expected,
    ):
        sbox = "id-tc26-gost-28147-param-Z"
        content_info, tail = ContentInfo().decode(content_info_raw, ctx={
            "defines_by_path": [
                (
                    (
                        "content",
                        DecodePathDefBy(id_envelopedData),
                        "recipientInfos",
                        any,
                        "ktri",
                        "encryptedKey",
                        DecodePathDefBy(spki_algorithm),
                        "transportParameters",
                        "ephemeralPublicKey",
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
                ) for spki_algorithm in (
                    id_tc26_gost3410_2012_256,
                    id_tc26_gost3410_2012_512,
                )
            ],
        })
        self.assertSequenceEqual(tail, b"")
        self.assertIsNotNone(content_info["content"].defined)
        _, enveloped_data = content_info["content"].defined
        eci = enveloped_data["encryptedContentInfo"]
        ri = enveloped_data["recipientInfos"][0]
        self.assertIsNotNone(ri["ktri"]["encryptedKey"].defined)
        _, encrypted_key = ri["ktri"]["encryptedKey"].defined
        ukm = bytes(encrypted_key["transportParameters"]["ukm"])
        spk = encrypted_key["transportParameters"]["ephemeralPublicKey"]["subjectPublicKey"]
        self.assertIsNotNone(spk.defined)
        _, pub_key_their = spk.defined
        curve = CURVES[curve_name]
        kek = keker(curve, prv_key_our, bytes(pub_key_their), ukm)
        key_wrapped = bytes(encrypted_key["sessionEncryptedKey"]["encryptedKey"])
        mac = bytes(encrypted_key["sessionEncryptedKey"]["macKey"])
        cek = unwrap_cryptopro(kek, ukm + key_wrapped + mac, sbox=sbox)
        ciphertext = bytes(eci["encryptedContent"])
        self.assertIsNotNone(eci["contentEncryptionAlgorithm"]["parameters"].defined)
        _, encryption_params = eci["contentEncryptionAlgorithm"]["parameters"].defined
        iv = bytes(encryption_params["iv"])
        self.assertSequenceEqual(
            cfb_decrypt(cek, ciphertext, iv, sbox=sbox, mesh=True),
            plaintext_expected,
        )

    def test_256(self):
        content_info_raw = b64decode("""
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
        """)
        prv_key_our = hexdec("BFCF1D623E5CDD3032A7C6EABB4A923C46E43D640FFEAAF2C3ED39A8FA399924")[::-1]

        def keker(curve, prv, pub, ukm):
            return kek_34102012256(
                curve,
                prv_unmarshal(prv),
                pub_unmarshal(pub),
                ukm_unmarshal(ukm),
                mode=2001,
            )

        self.process_cms(
            content_info_raw,
            prv_key_our,
            "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
            keker,
            b"Test data to encrypt.\n" * 100,
        )

    def test_512(self):
        content_info_raw = b64decode("""
MIIB0gYJKoZIhvcNAQcDoIIBwzCCAb8CAQAxggF8MIIBeAIBADBbMFYxKTAnBgkq
hkiG9w0BCQEWGkdvc3RSMzQxMC0yMDEyQGV4YW1wbGUuY29tMSkwJwYDVQQDEyBH
b3N0UjM0MTAtMjAxMiA1MTIgYml0cyBleGNoYW5nZQIBATAhBggqhQMHAQEBAjAV
BgkqhQMHAQIBAgIGCCqFAwcBAQIDBIHyMIHvMCgEIIsYzbVLn33aLinQ7SLNA7y+
Lrm02khqDCfXrNS9iiMhBATerS8zoIHCBgkqhQMHAQIFAQGggaowIQYIKoUDBwEB
AQIwFQYJKoUDBwECAQICBggqhQMHAQECAwOBhAAEgYAYiTVLKpSGaAvjJEDQ0hdK
qR/jek5Q9Q2pXC+NkOimQh7dpCi+wcaHlPcBk96hmpnOFvLaiokX8V6jqtBl5gdk
M40kOXv8kcDdTzEVKA/ZLxA8xanL+gTD6ZjaPsUu06nsA2MoMBWcHLUzueaP3bGT
/yHTV+Za5xdcQehag/lNBgQIvCw4uUl0XC4wOgYJKoZIhvcNAQcBMB8GBiqFAwIC
FTAVBAj+1QzaXaN9FwYJKoUDBwECBQEBgAyK54euw0sHhEVEkA0=
        """)
        prv_key_our = hexdec("3FC01CDCD4EC5F972EB482774C41E66DB7F380528DFE9E67992BA05AEE462435757530E641077CE587B976C8EEB48C48FD33FD175F0C7DE6A44E014E6BCB074B")[::-1]

        def keker(curve, prv, pub, ukm):
            return kek_34102012256(
                curve,
                prv_unmarshal(prv),
                pub_unmarshal(pub, mode=2012),
                ukm_unmarshal(ukm),
            )

        self.process_cms(
            content_info_raw,
            prv_key_our,
            "id-tc26-gost-3410-12-512-paramSetB",
            keker,
            b"Test message",
        )


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestEnvelopedKARI(TestCase):
    """EnvelopedData KeyAgreeRecipientInfo-based test vectors from
    "Использование алгоритмов ГОСТ 28147-89, ГОСТ Р 34.11 и ГОСТ Р 34.10
    в криптографических сообщениях формата CMS" (TK26CMS.pdf)
    """

    def process_cms(
            self,
            content_info_raw,
            prv_key_our,
            curve_name,
            keker,
            plaintext_expected,
    ):
        sbox = "id-tc26-gost-28147-param-Z"
        content_info, tail = ContentInfo().decode(content_info_raw, ctx={
            "defines_by_path": [
                (
                    (
                        "content",
                        DecodePathDefBy(id_envelopedData),
                        "recipientInfos",
                        any,
                        "kari",
                        "originator",
                        "originatorKey",
                        "algorithm",
                        "algorithm",
                    ),
                    (
                        (
                            ("..", "publicKey"),
                            {
                                id_tc26_gost3410_2012_256: OctetString(),
                                id_tc26_gost3410_2012_512: OctetString(),
                            },
                        ),
                    ),
                ) for _ in (
                    id_tc26_gost3410_2012_256,
                    id_tc26_gost3410_2012_512,
                )
            ],
        })
        self.assertSequenceEqual(tail, b"")
        self.assertIsNotNone(content_info["content"].defined)
        _, enveloped_data = content_info["content"].defined
        eci = enveloped_data["encryptedContentInfo"]
        kari = enveloped_data["recipientInfos"][0]["kari"]
        self.assertIsNotNone(kari["originator"]["originatorKey"]["publicKey"].defined)
        _, pub_key_their = kari["originator"]["originatorKey"]["publicKey"].defined
        ukm = bytes(kari["ukm"])
        rek = kari["recipientEncryptedKeys"][0]
        curve = CURVES[curve_name]
        kek = keker(curve, prv_key_our, bytes(pub_key_their), ukm)
        self.assertIsNotNone(rek["encryptedKey"].defined)
        _, encrypted_key = rek["encryptedKey"].defined
        key_wrapped = bytes(encrypted_key["encryptedKey"])
        mac = bytes(encrypted_key["macKey"])
        cek = unwrap_gost(kek, ukm + key_wrapped + mac, sbox=sbox)
        ciphertext = bytes(eci["encryptedContent"])
        self.assertIsNotNone(eci["contentEncryptionAlgorithm"]["parameters"].defined)
        _, encryption_params = eci["contentEncryptionAlgorithm"]["parameters"].defined
        iv = bytes(encryption_params["iv"])
        self.assertSequenceEqual(
            cfb_decrypt(cek, ciphertext, iv, sbox=sbox, mesh=True),
            plaintext_expected,
        )

    def test_256(self):
        content_info_raw = b64decode("""
MIIBhgYJKoZIhvcNAQcDoIIBdzCCAXMCAQIxggEwoYIBLAIBA6BooWYwHwYIKoUD
BwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIDQwAEQPAdWM4pO38iZ49UjaXQpq+a
jhTa4KwY4B9TFMK7AiYmbFKE0eX/wvu69kFMQ2o3OJTnMOlr1WHiPYOmNO6C5hOh
CgQIX+vNomZakEIwIgYIKoUDBwEBAQEwFgYHKoUDAgINADALBgkqhQMHAQIFAQEw
gYwwgYkwWzBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxl
LmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgMjU2IGJpdHMgZXhjaGFuZ2UC
AQEEKjAoBCCNhrZOr7x2fsjjQAeDMv/tSoNRQSSQzzxgqdnYxJ3fIAQEgYLqVDA6
BgkqhkiG9w0BBwEwHwYGKoUDAgIVMBUECHVmR/S+hlYiBgkqhQMHAQIFAQGADEI9
UNjyuY+54uVcHw==
        """)
        prv_key_our = hexdec("BFCF1D623E5CDD3032A7C6EABB4A923C46E43D640FFEAAF2C3ED39A8FA399924")[::-1]

        def keker(curve, prv, pub, ukm):
            return kek_34102012256(
                curve,
                prv_unmarshal(prv),
                pub_unmarshal(pub),
                ukm_unmarshal(ukm),
                mode=2001,
            )

        self.process_cms(
            content_info_raw,
            prv_key_our,
            "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
            keker,
            b"Test message",
        )

    def test_512(self):
        content_info_raw = b64decode("""
MIIBzAYJKoZIhvcNAQcDoIIBvTCCAbkCAQIxggF2oYIBcgIBA6CBraGBqjAhBggq
hQMHAQEBAjAVBgkqhQMHAQIBAgIGCCqFAwcBAQIDA4GEAASBgCB0nQy/Ljva/mRj
w6o+eDKIvnxwYIQB5XCHhZhCpHNZiWcFxFpYXZLWRPKifOxV7NStvqGE1+fkfhBe
btkQu0tdC1XL3LO2Cp/jX16XhW/IP5rKV84qWr1Owy/6tnSsNRb+ez6IttwVvaVV
pA6ONFy9p9gawoC8nitvAVJkWW0PoQoECDVfxzxgMTAHMCIGCCqFAwcBAQECMBYG
ByqFAwICDQAwCwYJKoUDBwECBQEBMIGMMIGJMFswVjEpMCcGCSqGSIb3DQEJARYa
R29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RSMzQxMC0y
MDEyIDUxMiBiaXRzIGV4Y2hhbmdlAgEBBCowKAQg8C/OcxRR0Uq8nDjHrQlayFb3
WFUZEnEuAKcuG6dTOawEBLhi9hIwOgYJKoZIhvcNAQcBMB8GBiqFAwICFTAVBAiD
1wH+CX6CwgYJKoUDBwECBQEBgAzUvQI4H2zRfgNgdlY=
        """)
        prv_key_our = hexdec("3FC01CDCD4EC5F972EB482774C41E66DB7F380528DFE9E67992BA05AEE462435757530E641077CE587B976C8EEB48C48FD33FD175F0C7DE6A44E014E6BCB074B")[::-1]

        def keker(curve, prv, pub, ukm):
            return kek_34102012256(
                curve,
                prv_unmarshal(prv),
                pub_unmarshal(pub, mode=2012),
                ukm_unmarshal(ukm),
            )

        self.process_cms(
            content_info_raw,
            prv_key_our,
            "id-tc26-gost-3410-12-512-paramSetB",
            keker,
            b"Test message",
        )
