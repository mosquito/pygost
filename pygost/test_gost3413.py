from os import urandom
from random import randint
from unittest import TestCase

from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3412 import GOST3412Magma
from pygost.gost3413 import _mac_ks
from pygost.gost3413 import cbc_decrypt
from pygost.gost3413 import cbc_encrypt
from pygost.gost3413 import cfb_decrypt
from pygost.gost3413 import cfb_encrypt
from pygost.gost3413 import ctr
from pygost.gost3413 import ecb_decrypt
from pygost.gost3413 import ecb_encrypt
from pygost.gost3413 import mac
from pygost.gost3413 import ofb
from pygost.gost3413 import pad2
from pygost.gost3413 import unpad2
from pygost.utils import hexdec
from pygost.utils import hexenc


class Pad2Test(TestCase):
    def test_symmetric(self):
        for _ in range(100):
            for blocksize in (8, 16):
                data = urandom(randint(0, blocksize * 3))
                self.assertSequenceEqual(
                    unpad2(pad2(data, blocksize), blocksize),
                    data,
                )


class GOST3412KuznechikModesTest(TestCase):
    key = hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    ciph = GOST3412Kuznechik(key)
    plaintext = ""
    plaintext += "1122334455667700ffeeddccbbaa9988"
    plaintext += "00112233445566778899aabbcceeff0a"
    plaintext += "112233445566778899aabbcceeff0a00"
    plaintext += "2233445566778899aabbcceeff0a0011"
    iv = hexdec("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")

    def test_ecb_vectors(self):
        ciphtext = ""
        ciphtext += "7f679d90bebc24305a468d42b9d4edcd"
        ciphtext += "b429912c6e0032f9285452d76718d08b"
        ciphtext += "f0ca33549d247ceef3f5a5313bd4b157"
        ciphtext += "d0b09ccde830b9eb3a02c4c5aa8ada98"
        self.assertSequenceEqual(
            hexenc(ecb_encrypt(self.ciph.encrypt, 16, hexdec(self.plaintext))),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ecb_decrypt(self.ciph.decrypt, 16, hexdec(ciphtext))),
            self.plaintext,
        )

    def test_ecb_symmetric(self):
        for _ in range(100):
            pt = pad2(urandom(randint(0, 16 * 2)), 16)
            ciph = GOST3412Kuznechik(urandom(32))
            ct = ecb_encrypt(ciph.encrypt, 16, pt)
            self.assertSequenceEqual(ecb_decrypt(ciph.decrypt, 16, ct), pt)

    def test_ctr_vectors(self):
        ciphtext = ""
        ciphtext += "f195d8bec10ed1dbd57b5fa240bda1b8"
        ciphtext += "85eee733f6a13e5df33ce4b33c45dee4"
        ciphtext += "a5eae88be6356ed3d5e877f13564a3a5"
        ciphtext += "cb91fab1f20cbab6d1c6d15820bdba73"
        iv = self.iv[:8]
        self.assertSequenceEqual(
            hexenc(ctr(self.ciph.encrypt, 16, hexdec(self.plaintext), iv)),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ctr(self.ciph.encrypt, 16, hexdec(ciphtext), iv)),
            self.plaintext,
        )

    def test_ctr_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(8)
            ciph = GOST3412Kuznechik(urandom(32))
            ct = ctr(ciph.encrypt, 16, pt, iv)
            self.assertSequenceEqual(ctr(ciph.encrypt, 16, ct, iv), pt)

    def test_ofb_vectors(self):
        ciphtext = ""
        ciphtext += "81800a59b1842b24ff1f795e897abd95"
        ciphtext += "ed5b47a7048cfab48fb521369d9326bf"
        ciphtext += "66a257ac3ca0b8b1c80fe7fc10288a13"
        ciphtext += "203ebbc066138660a0292243f6903150"
        self.assertSequenceEqual(
            hexenc(ofb(self.ciph.encrypt, 16, hexdec(self.plaintext), self.iv)),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ofb(self.ciph.encrypt, 16, hexdec(ciphtext), self.iv)),
            self.plaintext,
        )

    def test_ofb_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(16 * 2)
            ciph = GOST3412Kuznechik(urandom(32))
            ct = ofb(ciph.encrypt, 16, pt, iv)
            self.assertSequenceEqual(ofb(ciph.encrypt, 16, ct, iv), pt)

    def test_cbc_vectors(self):
        ciphtext = ""
        ciphtext += "689972d4a085fa4d90e52e3d6d7dcc27"
        ciphtext += "2826e661b478eca6af1e8e448d5ea5ac"
        ciphtext += "fe7babf1e91999e85640e8b0f49d90d0"
        ciphtext += "167688065a895c631a2d9a1560b63970"
        self.assertSequenceEqual(
            hexenc(cbc_encrypt(self.ciph.encrypt, 16, hexdec(self.plaintext), self.iv)),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(cbc_decrypt(self.ciph.decrypt, 16, hexdec(ciphtext), self.iv)),
            self.plaintext,
        )

    def test_cbc_symmetric(self):
        for _ in range(100):
            pt = pad2(urandom(randint(0, 16 * 2)), 16)
            iv = urandom(16 * 2)
            ciph = GOST3412Kuznechik(urandom(32))
            ct = cbc_encrypt(ciph.encrypt, 16, pt, iv)
            self.assertSequenceEqual(cbc_decrypt(ciph.decrypt, 16, ct, iv), pt)

    def test_cfb_vectors(self):
        ciphtext = ""
        ciphtext += "81800a59b1842b24ff1f795e897abd95"
        ciphtext += "ed5b47a7048cfab48fb521369d9326bf"
        ciphtext += "79f2a8eb5cc68d38842d264e97a238b5"
        ciphtext += "4ffebecd4e922de6c75bd9dd44fbf4d1"
        self.assertSequenceEqual(
            hexenc(cfb_encrypt(self.ciph.encrypt, 16, hexdec(self.plaintext), self.iv)),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(cfb_decrypt(self.ciph.encrypt, 16, hexdec(ciphtext), self.iv)),
            self.plaintext,
        )

    def test_cfb_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(16 * 2)
            ciph = GOST3412Kuznechik(urandom(32))
            ct = cfb_encrypt(ciph.encrypt, 16, pt, iv)
            self.assertSequenceEqual(cfb_decrypt(ciph.encrypt, 16, ct, iv), pt)

    def test_mac_vectors(self):
        k1, k2 = _mac_ks(self.ciph.encrypt, 16)
        self.assertSequenceEqual(hexenc(k1), "297d82bc4d39e3ca0de0573298151dc7")
        self.assertSequenceEqual(hexenc(k2), "52fb05789a73c7941bc0ae65302a3b8e")
        self.assertSequenceEqual(
            hexenc(mac(self.ciph.encrypt, 16, hexdec(self.plaintext))[:8]),
            "336f4d296059fbe3",
        )

    def test_mac_applies(self):
        for _ in range(100):
            data = urandom(randint(0, 16 * 2))
            ciph = GOST3412Kuznechik(urandom(32))
            mac(ciph.encrypt, 16, data)


class GOST3412MagmaModesTest(TestCase):
    key = hexdec("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ciph = GOST3412Magma(key)
    plaintext = ""
    plaintext += "92def06b3c130a59"
    plaintext += "db54c704f8189d20"
    plaintext += "4a98fb2e67a8024c"
    plaintext += "8912409b17b57e41"
    iv = hexdec("1234567890abcdef234567890abcdef134567890abcdef12")

    def test_ecb_vectors(self):
        ciphtext = ""
        ciphtext += "2b073f0494f372a0"
        ciphtext += "de70e715d3556e48"
        ciphtext += "11d8d9e9eacfbc1e"
        ciphtext += "7c68260996c67efb"
        self.assertSequenceEqual(
            hexenc(ecb_encrypt(self.ciph.encrypt, 8, hexdec(self.plaintext))),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ecb_decrypt(self.ciph.decrypt, 8, hexdec(ciphtext))),
            self.plaintext,
        )

    def test_ecb_symmetric(self):
        for _ in range(100):
            pt = pad2(urandom(randint(0, 16 * 2)), 16)
            ciph = GOST3412Magma(urandom(32))
            ct = ecb_encrypt(ciph.encrypt, 8, pt)
            self.assertSequenceEqual(ecb_decrypt(ciph.decrypt, 8, ct), pt)

    def test_ctr_vectors(self):
        ciphtext = ""
        ciphtext += "4e98110c97b7b93c"
        ciphtext += "3e250d93d6e85d69"
        ciphtext += "136d868807b2dbef"
        ciphtext += "568eb680ab52a12d"
        iv = self.iv[:4]
        self.assertSequenceEqual(
            hexenc(ctr(self.ciph.encrypt, 8, hexdec(self.plaintext), iv)),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ctr(self.ciph.encrypt, 8, hexdec(ciphtext), iv)),
            self.plaintext,
        )

    def test_ctr_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(4)
            ciph = GOST3412Magma(urandom(32))
            ct = ctr(ciph.encrypt, 8, pt, iv)
            self.assertSequenceEqual(ctr(ciph.encrypt, 8, ct, iv), pt)

    def test_ofb_vectors(self):
        iv = self.iv[:16]
        ciphtext = ""
        ciphtext += "db37e0e266903c83"
        ciphtext += "0d46644c1f9a089c"
        ciphtext += "a0f83062430e327e"
        ciphtext += "c824efb8bd4fdb05"
        self.assertSequenceEqual(
            hexenc(ofb(self.ciph.encrypt, 8, hexdec(self.plaintext), iv)),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(ofb(self.ciph.encrypt, 8, hexdec(ciphtext), iv)),
            self.plaintext,
        )

    def test_ofb_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(8 * 2)
            ciph = GOST3412Magma(urandom(32))
            ct = ofb(ciph.encrypt, 8, pt, iv)
            self.assertSequenceEqual(ofb(ciph.encrypt, 8, ct, iv), pt)

    def test_cbc_vectors(self):
        ciphtext = ""
        ciphtext += "96d1b05eea683919"
        ciphtext += "aff76129abb937b9"
        ciphtext += "5058b4a1c4bc0019"
        ciphtext += "20b78b1a7cd7e667"
        self.assertSequenceEqual(
            hexenc(cbc_encrypt(self.ciph.encrypt, 8, hexdec(self.plaintext), self.iv)),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(cbc_decrypt(self.ciph.decrypt, 8, hexdec(ciphtext), self.iv)),
            self.plaintext,
        )

    def test_cbc_symmetric(self):
        for _ in range(100):
            pt = pad2(urandom(randint(0, 16 * 2)), 16)
            iv = urandom(8 * 2)
            ciph = GOST3412Magma(urandom(32))
            ct = cbc_encrypt(ciph.encrypt, 8, pt, iv)
            self.assertSequenceEqual(cbc_decrypt(ciph.decrypt, 8, ct, iv), pt)

    def test_cfb_vectors(self):
        iv = self.iv[:16]
        ciphtext = ""
        ciphtext += "db37e0e266903c83"
        ciphtext += "0d46644c1f9a089c"
        ciphtext += "24bdd2035315d38b"
        ciphtext += "bcc0321421075505"
        self.assertSequenceEqual(
            hexenc(cfb_encrypt(self.ciph.encrypt, 8, hexdec(self.plaintext), iv)),
            ciphtext,
        )
        self.assertSequenceEqual(
            hexenc(cfb_decrypt(self.ciph.encrypt, 8, hexdec(ciphtext), iv)),
            self.plaintext,
        )

    def test_cfb_symmetric(self):
        for _ in range(100):
            pt = urandom(randint(0, 16 * 2))
            iv = urandom(8 * 2)
            ciph = GOST3412Magma(urandom(32))
            ct = cfb_encrypt(ciph.encrypt, 8, pt, iv)
            self.assertSequenceEqual(cfb_decrypt(ciph.encrypt, 8, ct, iv), pt)

    def test_mac_vectors(self):
        k1, k2 = _mac_ks(self.ciph.encrypt, 8)
        self.assertSequenceEqual(hexenc(k1), "5f459b3342521424")
        self.assertSequenceEqual(hexenc(k2), "be8b366684a42848")
        self.assertSequenceEqual(
            hexenc(mac(self.ciph.encrypt, 8, hexdec(self.plaintext))[:4]),
            "154e7210",
        )

    def test_mac_applies(self):
        for _ in range(100):
            data = urandom(randint(0, 16 * 2))
            ciph = GOST3412Magma(urandom(32))
            mac(ciph.encrypt, 8, data)
