# coding: utf-8

from base64 import b64decode
from unittest import skipIf
from unittest import TestCase

from pygost.gost28147 import cfb_decrypt
from pygost.gost3410 import CURVE_PARAMS
from pygost.gost3410 import GOST3410Curve
from pygost.gost3410 import prv_unmarshal
from pygost.gost3410 import pub_unmarshal
from pygost.gost3410_vko import kek_34102012256
from pygost.gost3410_vko import ukm_unmarshal
from pygost.utils import hexdec
from pygost.wrap import unwrap_cryptopro

try:

    from pyderasn import Any
    from pyderasn import BitString
    from pyderasn import Choice
    from pyderasn import Integer
    from pyderasn import ObjectIdentifier
    from pyderasn import OctetString
    from pyderasn import Sequence
    from pyderasn import SetOf
    from pyderasn import tag_ctxc
    from pyderasn import tag_ctxp

    class CMSVersion(Integer):
        pass

    class ContentType(ObjectIdentifier):
        pass

    class RecipientIdentifier(Choice):
        schema = (
            ("issuerAndSerialNumber", Any()),
            # ("subjectKeyIdentifier", SubjectKeyIdentifier(impl=tag_ctxp(0))),
        )

    class AlgorithmIdentifier(Sequence):
        schema = (
            ("algorithm", ObjectIdentifier()),
            ("parameters", Any(optional=True)),
        )

    class KeyEncryptionAlgorithmIdentifier(AlgorithmIdentifier):
        pass

    class EncryptedKey(OctetString):
        pass

    class KeyTransRecipientInfo(Sequence):
        schema = (
            ("version", CMSVersion()),
            ("rid", RecipientIdentifier()),
            ("keyEncryptionAlgorithm", KeyEncryptionAlgorithmIdentifier()),
            ("encryptedKey", EncryptedKey()),
        )

    class RecipientInfo(Choice):
        schema = (
            ("ktri", KeyTransRecipientInfo()),
            # ("kari", KeyAgreeRecipientInfo(impl=tag_ctxc(1))),
            # ("kekri", KEKRecipientInfo(impl=tag_ctxc(2))),
            # ("pwri", PasswordRecipientInfo(impl=tag_ctxc(3))),
            # ("ori", OtherRecipientInfo(impl=tag_ctxc(4))),
        )

    class RecipientInfos(SetOf):
        schema = RecipientInfo()
        bounds = (1, float("+inf"))

    class ContentEncryptionAlgorithmIdentifier(AlgorithmIdentifier):
        pass

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

    class ContentInfo(Sequence):
        schema = (
            ("contentType", ContentType()),
            ("content", Any(expl=tag_ctxc(0))),
        )

    class Gost2814789IV(OctetString):
        bounds = (8, 8)

    class Gost2814789Parameters(Sequence):
        schema = (
            ("iv", Gost2814789IV()),
            ("encryptionParamSet", ObjectIdentifier()),
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

    class SubjectPublicKeyInfo(Sequence):
        schema = (
            ("algorithm", AlgorithmIdentifier()),
            ("subjectPublicKey", BitString()),
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

except ImportError:
    pyderasn_exists = False
else:
    pyderasn_exists = True


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestCMSEnveloped(TestCase):
    """KeyTransRecipientInfo-based test vectors from "Использование
    алгоритмов ГОСТ 28147-89, ГОСТ Р 34.11 и ГОСТ Р 34.10 в
    криптографических сообщениях формата CMS" (TK26CMS.pdf)
    """

    def process_cms(
            self,
            content_info_raw,
            prv_key_our,
            curve_name,
            keker,
            plaintext_expected,
    ):
        sbox = "Gost28147_tc26_ParamZ"
        content_info, _ = ContentInfo().decode(content_info_raw)
        enveloped_data, _ = EnvelopedData().decode(bytes(content_info["content"]))
        eci = enveloped_data["encryptedContentInfo"]
        ri = enveloped_data["recipientInfos"][0]
        encrypted_key, _ = GostR3410KeyTransport().decode(
            bytes(ri["ktri"]["encryptedKey"])
        )
        ukm = bytes(encrypted_key["transportParameters"]["ukm"])
        spk = bytes(encrypted_key["transportParameters"]["ephemeralPublicKey"]["subjectPublicKey"])
        pub_key_their, _ = OctetString().decode(spk)
        curve = GOST3410Curve(*CURVE_PARAMS[curve_name])
        kek = keker(curve, prv_key_our, bytes(pub_key_their), ukm)
        key_wrapped = bytes(encrypted_key["sessionEncryptedKey"]["encryptedKey"])
        mac = bytes(encrypted_key["sessionEncryptedKey"]["macKey"])
        cek = unwrap_cryptopro(kek, ukm + key_wrapped + mac, sbox=sbox)
        ciphertext = bytes(eci["encryptedContent"])
        encryption_params, _ = Gost2814789Parameters().decode(
            bytes(eci["contentEncryptionAlgorithm"]["parameters"])
        )
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
            "GostR3410_2001_CryptoPro_XchA_ParamSet",
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
            "GostR3410_2012_TC26_ParamSetB",
            keker,
            b"Test message",
        )
