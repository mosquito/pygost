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
from hmac import new as hmac_new
from unittest import skipIf
from unittest import TestCase

from pygost.gost28147 import cfb_decrypt
from pygost.gost34112012512 import GOST34112012512
from pygost.gost34112012512 import pbkdf2 as gost34112012_pbkdf2
from pygost.utils import hexdec


try:
    from pygost.asn1schemas.pfx import OctetStringSafeContents
    from pygost.asn1schemas.pfx import PFX
    from pygost.asn1schemas.pfx import PKCS8ShroudedKeyBag
    from pygost.asn1schemas.pfx import SafeContents
except ImportError:
    pyderasn_exists = False
else:
    pyderasn_exists = True


@skipIf(not pyderasn_exists, "PyDERASN dependency is required")
class TestPFX(TestCase):
    """PFX test vectors from "Транспортный ключевой контейнер" (R50.1.112-2016.pdf)
    """
    pfx_raw = b64decode("""
MIIFqgIBAzCCBSsGCSqGSIb3DQEHAaCCBRwEggUYMIIFFDCCASIGCSqGSIb3DQEH
AaCCARMEggEPMIIBCzCCAQcGCyqGSIb3DQEMCgECoIHgMIHdMHEGCSqGSIb3DQEF
DTBkMEEGCSqGSIb3DQEFDDA0BCD5qZr0TTIsBvdgUoq/zFwOzdyJohj6/4Wiyccg
j9AK/QICB9AwDAYIKoUDBwEBBAIFADAfBgYqhQMCAhUwFQQI3Ip/Vp0IsyIGCSqF
AwcBAgUBAQRoSfLhgx9s/zn+BjnhT0ror07vS55Ys5hgvVpWDx4mXGWWyez/2sMc
aFgSr4H4UTGGwoMynGLpF1IOVo+bGJ0ePqHB+gS5OL9oV+PUmZ/ELrRENKlCDqfY
WvpSystX29CvCFrnTnDsbBYxFTATBgkqhkiG9w0BCRUxBgQEAQAAADCCA+oGCSqG
SIb3DQEHBqCCA9swggPXAgEAMIID0AYJKoZIhvcNAQcBMHEGCSqGSIb3DQEFDTBk
MEEGCSqGSIb3DQEFDDA0BCCJTJLZQRi1WIpQHzyjXbq7+Vw2+1280C45x8ff6kMS
VAICB9AwDAYIKoUDBwEBBAIFADAfBgYqhQMCAhUwFQQIxepowwvS11MGCSqFAwcB
AgUBAYCCA06n09P/o+eDEKoSWpvlpOLKs7dKmVquKzJ81nCngvLQ5fEWL1WkxwiI
rEhm53JKLD0wy4hekalEk011Bvc51XP9gkDkmaoBpnV/TyKIY35wl6ATfeGXno1M
KoA+Ktdhv4gLnz0k2SXdkUj11JwYskXue+REA0p4m2ZsoaTmvoODamh9JeY/5Qjy
Xe58CGnyXFzX3eU86qs4WfdWdS3NzYYOk9zzVl46le9u79O/LnW2j4n2of/Jpk/L
YjrRmz5oYeQOqKOKhEyhpO6e+ejr6laduEv7TwJQKRNiygogbVvkNn3VjHTSOUG4
W+3NRPhjb0jD9obdyx6MWa6O3B9bUzFMNav8/gYn0vTDxqXMLy/92oTngNrVx6Gc
cNl128ISrDS6+RxtAMiEBRK6xNkemqX5yNXG5GrLQQFGP6mbs2nNpjKlgj3pljmX
Eky2/G78XiJrv02OgGs6CKnI9nMpa6N7PBHV34MJ6EZzWOWDRQ420xk63mnicrs0
WDVJ0xjdu4FW3iEk02EaiRTvGBpa6GL7LBp6QlaXSSwONx725cyRsL9cTlukqXER
WHDlMpjYLbkGZRrCc1myWgEfsputfSIPNF/oLv9kJNWacP3uuDOfecg3us7eg2OA
xo5zrYfn39GcBMF1WHAYRO/+PnJb9jrDuLAE8+ONNqjNulWNK9CStEhb6Te+yE6q
oeP6hJjFLi+nFLE9ymIo0A7gLQD5vzFvl+7v1ZNVnQkwRUsWoRiEVVGnv3Z1iZU6
xStxgoHMl62V/P5cz4dr9vJM2adEWNZcVXl6mk1H8DRc1sRGnvs2l237oKWRVntJ
hoWnZ8qtD+3ZUqsX79QhVzUQBzKuBt6jwNhaHLGl5B+Or/zA9FezsOh6+Uc+fZaV
W7fFfeUyWwGy90XD3ybTrjzep9f3nt55Z2c+fu2iEwhoyImWLuC3+CVhf9Af59j9
8/BophMJuATDJEtgi8rt4vLnfxKu250Mv2ZpbfF69EGTgFYbwc55zRfaUG9zlyCu
1YwMJ6HC9FUVtJp9gObSrirbzTH7mVaMjQkBLotazWbegzI+be8V3yT06C+ehD+2
GdLWAVs9hp8gPHEUShb/XrgPpDSJmFlOiyeOFBO/j4edDACKqVcwdjBOMAoGCCqF
AwcBAQIDBEAIFX0fyZe20QKKhWm6WYX+S92Gt6zaXroXOvAmayzLfZ5Sd9C2t9zZ
JSg6M8RBUYpw/8ym5ou1o2nDa09M5zF3BCCpzyCQBI+rzfISeKvPV1ROfcXiYU93
mwcl1xQV2G5/fgICB9A=
    """)
    password = u'Пароль для PFX'

    def test_shrouded_key_bag(self):
        private_key_info_expected = b64decode(b"""
MGYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIEQEYbRu86z+1JFKDcPDN9UbTG
G2ki9enTqos4KpUU0j9IDpl1UXiaA1YDIwUjlAp+81GkLmyt8Fw6Gt/X5JZySAY=
        """)

        pfx, tail = PFX().decode(self.pfx_raw)
        self.assertSequenceEqual(tail, b"")
        _, outer_safe_contents = pfx["authSafe"]["content"].defined
        safe_contents, tail = OctetStringSafeContents().decode(
            bytes(outer_safe_contents[0]["bagValue"]),
        )
        self.assertSequenceEqual(tail, b"")
        safe_bag = safe_contents[0]
        shrouded_key_bag, tail = PKCS8ShroudedKeyBag().decode(
            bytes(safe_bag["bagValue"]),
        )
        self.assertSequenceEqual(tail, b"")
        _, pbes2_params = shrouded_key_bag["encryptionAlgorithm"]["parameters"].defined
        _, pbkdf2_params = pbes2_params["keyDerivationFunc"]["parameters"].defined
        _, enc_scheme_params = pbes2_params["encryptionScheme"]["parameters"].defined

        key = gost34112012_pbkdf2(
            password=self.password.encode("utf-8"),
            salt=bytes(pbkdf2_params["salt"]["specified"]),
            iterations=int(pbkdf2_params["iterationCount"]),
            dklen=32,
        )
        # key = hexdec("309dd0354c5603739403f2335e9e2055138f8b5c98b63009de0635eea1fd7ba8")
        self.assertSequenceEqual(
            cfb_decrypt(
                key,
                bytes(shrouded_key_bag["encryptedData"]),
                iv=bytes(enc_scheme_params["iv"]),
                sbox="id-tc26-gost-28147-param-Z",
            ),
            private_key_info_expected,
        )

    def test_encrypted_data(self):
        cert_bag_expected = b64decode(b"""
MIIDSjCCA0YGCyqGSIb3DQEMCgEDoIIDHjCCAxoGCiqGSIb3DQEJFgGgggMKBIIDBjCCAwIwggKt
oAMCAQICEAHQaF8xH5bAAAAACycJAAEwDAYIKoUDBwEBAwIFADBgMQswCQYDVQQGEwJSVTEVMBMG
A1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQKDAbQotCaMjYxKTAnBgNVBAMMIENBIGNlcnRpZmlj
YXRlIChQS0NTIzEyIGV4YW1wbGUpMB4XDTE1MDMyNzA3MjUwMFoXDTIwMDMyNzA3MjMwMFowZDEL
MAkGA1UEBhMCUlUxFTATBgNVBAcMDNCc0L7RgdC60LLQsDEPMA0GA1UECgwG0KLQmjI2MS0wKwYD
VQQDDCRUZXN0IGNlcnRpZmljYXRlIDEgKFBLQ1MjMTIgZXhhbXBsZSkwZjAfBggqhQMHAQEBATAT
BgcqhQMCAiMBBggqhQMHAQECAgNDAARA1xzymkpvr2dYJT8WTOX3Dt96/+hGsXNytUQpkWB5ImJM
4tg9AsC4RIUwV5H41MhG0uBRFweTzN6AsAdBvhTClYEJADI3MDkwMDAxo4IBKTCCASUwKwYDVR0Q
BCQwIoAPMjAxNTAzMjcwNzI1MDBagQ8yMDE2MDMyNzA3MjUwMFowDgYDVR0PAQH/BAQDAgTwMB0G
A1UdDgQWBBQhWOsRQ68yYN2Utg/owHoWcqsVbTAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
AwQwDAYDVR0TAQH/BAIwADCBmQYDVR0jBIGRMIGOgBQmnc7Xh5ykb5t/BMwOkxA4drfEmqFkpGIw
YDELMAkGA1UEBhMCUlUxFTATBgNVBAcMDNCc0L7RgdC60LLQsDEPMA0GA1UECgwG0KLQmjI2MSkw
JwYDVQQDDCBDQSBjZXJ0aWZpY2F0ZSAoUEtDUyMxMiBleGFtcGxlKYIQAdBoXvL8TSAAAAALJwkA
ATAMBggqhQMHAQEDAgUAA0EA9oq0Vvk8kkgIwkp0x0J5eKtia4MNTiwKAm7jgnCZIx3O98BThaTX
3ZQhEo2RL9pTCPr6wFMheeJ+YdGMReXvsjEVMBMGCSqGSIb3DQEJFTEGBAQBAAAA
        """)

        pfx, tail = PFX().decode(self.pfx_raw)
        self.assertSequenceEqual(tail, b"")
        _, outer_safe_contents = pfx["authSafe"]["content"].defined
        _, encrypted_data = outer_safe_contents[1]["bagValue"].defined
        _, pbes2_params = encrypted_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"].defined
        _, pbkdf2_params = pbes2_params["keyDerivationFunc"]["parameters"].defined
        _, enc_scheme_params = pbes2_params["encryptionScheme"]["parameters"].defined
        key = gost34112012_pbkdf2(
            password=self.password.encode("utf-8"),
            salt=bytes(pbkdf2_params["salt"]["specified"]),
            iterations=int(pbkdf2_params["iterationCount"]),
            dklen=32,
        )
        # key = hexdec("0e93d71339e7f53b79a0bc41f9109dd4fb60b30ae10736c1bb77b84c07681cfc")
        self.assertSequenceEqual(
            cfb_decrypt(
                key,
                bytes(encrypted_data["encryptedContentInfo"]["encryptedContent"]),
                iv=bytes(enc_scheme_params["iv"]),
                sbox="id-tc26-gost-28147-param-Z",
            ),
            cert_bag_expected,
        )

    def test_mac(self):
        pfx, tail = PFX().decode(self.pfx_raw)
        self.assertSequenceEqual(tail, b"")
        _, outer_safe_contents = pfx["authSafe"]["content"].defined
        mac_data = pfx["macData"]
        mac_key = gost34112012_pbkdf2(
            password=self.password.encode('utf-8'),
            salt=bytes(mac_data["macSalt"]),
            iterations=int(mac_data["iterations"]),
            dklen=96,
        )[-32:]
        # mac_key = hexdec("cadbfbf3bceaa9b79f651508fac5abbeb4a13d0bd0e1876bd3c3efb2112128a5")
        self.assertSequenceEqual(
            hmac_new(
                key=mac_key,
                msg=SafeContents(outer_safe_contents).encode(),
                digestmod=GOST34112012512,
            ).digest(),
            bytes(mac_data["mac"]["digest"]),
        )
