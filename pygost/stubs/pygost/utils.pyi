from typing import AnyStr
from typing import Optional


def strxor(a: bytes, b: bytes) -> bytes: ...


def hexdec(data: AnyStr) -> bytes: ...


def hexenc(data: bytes) -> str: ...


def bytes2long(raw: bytes) -> int: ...


def long2bytes(n: int, size: int=...) -> bytes: ...


def modinvert(a: int, n: int) -> int: ...
