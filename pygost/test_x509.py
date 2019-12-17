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
from pygost.gost3410 import pub_unmarshal
from pygost.gost3410 import public_key
from pygost.gost3410 import verify
from pygost.gost34112012256 import GOST34112012256
from pygost.gost34112012512 import GOST34112012512
from pygost.utils import hexdec

try:
    from pyderasn import OctetString

    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256
    from pygost.asn1schemas.oids import id_tc26_gost3410_2012_512
    from pygost.asn1schemas.x509 import Certificate
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
