from typing import Dict
from typing import Tuple


CURVE_PARAMS = ...  # type: Dict[str, Tuple[bytes, bytes, bytes, bytes, bytes, bytes]]
PublicKey = Tuple[int, int]


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


def public_key(curve: GOST3410Curve, prv: int) -> PublicKey: ...


def sign(curve: GOST3410Curve, prv: int, digest: bytes, mode: int=...) -> bytes: ...


def verify(
    curve: GOST3410Curve,
    pub: PublicKey,
    digest: bytes,
    signature: bytes,
    mode: int=...,
) -> bool: ...


def prv_unmarshal(prv: bytes) -> int: ...


def pub_marshal(pub: PublicKey, mode: int=...) -> bytes: ...


def pub_unmarshal(pub: bytes, mode: int=...) -> PublicKey: ...
