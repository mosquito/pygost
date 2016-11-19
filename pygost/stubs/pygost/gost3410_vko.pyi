from pygost.gost3410 import GOST3410Curve
from pygost.gost3410 import PublicKey


def vko_34102001(
    curve: GOST3410Curve,
    private_key: int ,
    pubkey: PublicKey,
    ukm: bytes,
) -> bytes: ...


def vko_34102012256(
    curve: GOST3410Curve,
    private_key: int,
    pubkey: PublicKey,
    ukm=...: bytes,
) -> bytes: ...


def vko_34102012512(
    curve: GOST3410Curve,
    private_key: int,
    pubkey: PublicKey,
    ukm=...: bytes,
) -> bytes: ...
