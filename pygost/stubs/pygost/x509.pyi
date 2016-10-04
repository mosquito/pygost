from typing import Tuple


SIZE_3410_2001 = ...  # type: int
SIZE_3410_2012 = ...  # type: int


def keypair_gen(
    seed: bytes,
    mode: int=...,
    curve_params: str=...,
) -> Tuple[bytes, bytes]: ...


def sign_digest(
    private_key: bytes,
    digest: bytes,
    mode: int=...,
    curve_params: str=...,
) -> bytes: ...


def verify_digest(
    public_key: bytes,
    digest: bytes,
    signature: bytes,
    mode: int=...,
    curve_params: str=...,
) -> bool: ...


def sign(
    private_key: bytes,
    data: bytes,
    mode: int=...,
    curve_params: str=...,
) -> bytes: ...


def verify(
    public_key: bytes,
    data: bytes,
    signature: bytes,
    mode: int=...,
    curve_params: str=...,
) -> bool: ...
