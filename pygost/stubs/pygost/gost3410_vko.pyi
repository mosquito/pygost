from pygost.gost3410 import GOST3410Curve
from pygost.gost3410 import PublicKey


def ukm_unmarshal(ukm: bytes) -> int: ...


def kek_34102001(curve: GOST3410Curve, prv: int, pub: PublicKey, ukm: int) -> bytes: ...


def kek_34102012256(curve: GOST3410Curve, prv: int, pub: PublicKey, ukm: int=..., mode: int=...) -> bytes: ...


def kek_34102012512(curve: GOST3410Curve, prv: int, pub: PublicKey, ukm: int=...) -> bytes: ...
