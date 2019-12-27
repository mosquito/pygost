from typing import Dict
from typing import Tuple


DEFAULT_CURVE = ...  # type: GOST3410Curve
CURVES = ...  # type: Dict[str, GOST3410Curve]
MODE2SIZE = ...  # type: Dict[int, int]
PublicKey = Tuple[int, int]


class GOST3410Curve(object):
    p = ...  # type: int
    q = ...  # type: int
    a = ...  # type: int
    b = ...  # type: int
    x = ...  # type: int
    y = ...  # type: int
    e = ...  # type: int
    d = ...  # type: int

    def __init__(
            self,
            p: int,
            q: int,
            a: int,
            b: int,
            x: int,
            y: int,
            e: int = None,
            d: int = None,
    ) -> None: ...

    def pos(self, v: int) -> int: ...

    def exp(self, degree: int, x: int=..., y: int=...) -> int: ...

    def st(self) -> Tuple[int, int]: ...


def public_key(curve: GOST3410Curve, prv: int) -> PublicKey: ...


def sign(
        curve: GOST3410Curve,
        prv: int,
        digest: bytes,
        rand: bytes=None,
        mode: int=...,
) -> bytes: ...


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


def uv2xy(curve: GOST3410Curve, u: int, v: int) -> Tuple[int, int]: ...


def xy2uv(curve: GOST3410Curve, x: int, y: int) -> Tuple[int, int]: ...
