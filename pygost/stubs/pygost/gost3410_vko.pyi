from pygost.gost3410 import GOST3410Curve
from pygost.gost3410 import PublicKey


def ukm_unmarshal(ukm: bytes) -> int: ...


def vko_34102001(curve: GOST3410Curve, prv: int, pubkey: PublicKey, ukm: int) -> bytes: ...


def vko_34102012256(curve: GOST3410Curve, prv: int, pubkey: PublicKey, ukm: int=...) -> bytes: ...


def vko_34102012512(curve: GOST3410Curve, prv: int, pubkey: PublicKey, ukm: int=...) -> bytes: ...
