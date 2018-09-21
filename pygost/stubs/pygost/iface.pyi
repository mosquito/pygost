from abc import ABCMeta
from abc import abstractmethod


class PEP247(metaclass=ABCMeta):
    @abstractmethod
    @property
    def digest_size(self) -> int: ...

    @abstractmethod
    def copy(self) -> "PEP247": ...

    @abstractmethod
    def update(self, data: bytes) -> None: ...

    @abstractmethod
    def digest(self) -> bytes: ...

    def hexdigest(self) -> str: ...
