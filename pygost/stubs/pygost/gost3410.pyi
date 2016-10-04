from typing import Dict
from typing import Tuple


CURVE_PARAMS = ...  # type: Dict[str, Tuple[bytes, bytes, bytes, bytes, bytes, bytes]]


class GOST3410Curve(object):
    p = ...  # type: int
    q = ...  # type: int
    a = ...  # type: int
    b = ...  # type: int
    x = ...  # type: int
    y = ...  # type: int

    def __init__(
        self, p: bytes, q: bytes, a: bytes, b: bytes, x: bytes, y: bytes
    ) -> None: ...

    def exp(self, degree: int, x: int=..., y: int=...) -> int: ...


PublicKey = Tuple[int, int]


def public_key(curve: GOST3410Curve, private_key: int) -> PublicKey: ...


def kek(
    curve: GOST3410Curve,
    private_key: int,
    ukm: bytes,
    pubkey: PublicKey,
) -> bytes: ...


def sign(
    curve: GOST3410Curve,
    private_key: int,
    digest: bytes,
    size: int=...,
) -> bytes: ...


def verify(
    curve: GOST3410Curve,
    pubkeyX: int,
    pubkeyY: int,
    digest: bytes,
    signature: bytes,
    size: int=...,
) -> bool: ...
