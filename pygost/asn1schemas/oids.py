from pyderasn import ObjectIdentifier


id_pkcs7 = ObjectIdentifier("1.2.840.113549.1.7")
id_signedData = id_pkcs7 + (2,)
id_envelopedData = id_pkcs7 + (3,)
id_digestedData = id_pkcs7 + (5,)
id_encryptedData = id_pkcs7 + (6,)

id_data = ObjectIdentifier("1.2.840.113549.1.7.1")
id_tc26_gost3410_2012_256 = ObjectIdentifier("1.2.643.7.1.1.1.1")
id_tc26_gost3410_2012_512 = ObjectIdentifier("1.2.643.7.1.1.1.2")
id_tc26_gost3411_2012_256 = ObjectIdentifier("1.2.643.7.1.1.2.2")
id_tc26_gost3411_2012_512 = ObjectIdentifier("1.2.643.7.1.1.2.3")
id_tc26_gost3410_2012_256_paramSetA = ObjectIdentifier("1.2.643.7.1.2.1.1.1")
id_tc26_gost3410_2012_256_paramSetB = ObjectIdentifier("1.2.643.7.1.2.1.1.2")
id_tc26_gost3410_2012_256_paramSetC = ObjectIdentifier("1.2.643.7.1.2.1.1.3")
id_tc26_gost3410_2012_256_paramSetD = ObjectIdentifier("1.2.643.7.1.2.1.1.4")
id_tc26_gost3410_2012_512_paramSetA = ObjectIdentifier("1.2.643.7.1.2.1.2.1")
id_tc26_gost3410_2012_512_paramSetB = ObjectIdentifier("1.2.643.7.1.2.1.2.2")
id_tc26_gost3410_2012_512_paramSetC = ObjectIdentifier("1.2.643.7.1.2.1.2.3")
id_tc26_signwithdigest_gost3410_2012_256 = ObjectIdentifier("1.2.643.7.1.1.3.2")
id_tc26_signwithdigest_gost3410_2012_512 = ObjectIdentifier("1.2.643.7.1.1.3.3")
id_Gost28147_89 = ObjectIdentifier("1.2.643.2.2.21")

id_pbes2 = ObjectIdentifier("1.2.840.113549.1.5.13")
id_pbkdf2 = ObjectIdentifier("1.2.840.113549.1.5.12")

id_ce_subjectKeyIdentifier = ObjectIdentifier("2.5.29.14")
