from typing import Callable
from typing import Dict
from typing import Sequence
from typing import Tuple


SBOXES = ...  # type: Dict[str, Tuple[Tuple[int, ...], ...]]
BLOCKSIZE = ...  # type: int

Words = Tuple[int, int]


def block2ns(data: bytes) -> Words: ...


def ns2block(ns: Words) -> bytes: ...


def addmod(x: int, y: int, mod: int=...) -> int: ...


def validate_key(key: bytes) -> None: ...


def validate_iv(iv: bytes) -> None: ...


def validate_sbox(sbox: str) -> None: ...


def xcrypt(seq: Sequence[int], sbox: str, key: bytes, ns: Words) -> Words: ...


def encrypt(sbox: str, key: bytes, ns: Words) -> Words: ...


def decrypt(sbox: str, key: bytes, ns: Words) -> Words: ...


def ecb(
    key: bytes,
    data: bytes,
    action: Callable[[str, bytes, Words], Words],
    sbox: str=...,
) -> bytes: ...


def ecb_encrypt(
    key: bytes,
    data: bytes,
    sbox: str=...,
) -> bytes: ...


def ecb_decrypt(
    key: bytes,
    data: bytes,
    sbox: str=...,
) -> bytes: ...


def cbc_encrypt(
    key: bytes,
    data: bytes,
    iv: bytes=...,
    pad: bool=...,
    sbox: str=...,
    mesh: bool=...,
) -> bytes: ...


def cbc_decrypt(
    key: bytes,
    data: bytes,
    pad: bool=...,
    sbox: str=...,
    mesh: bool=...,
) -> bytes: ...


def cnt(
    key: bytes,
    data: bytes,
    iv: bytes=...,
    sbox: str=...,
) -> bytes: ...


def cfb_encrypt(
    key: bytes,
    data: bytes,
    iv: bytes=...,
    sbox: str=...,
    mesh: bool=...,
) -> bytes: ...


def cfb_decrypt(
    key: bytes,
    data: bytes,
    iv: bytes=...,
    sbox: str=...,
    mesh: bool=...,
) -> bytes: ...
