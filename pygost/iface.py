from abc import ABCMeta
from abc import abstractmethod

from pygost.utils import hexenc


# This function is taken from six package as is
def add_metaclass(metaclass):
    """Class decorator for creating a class with a metaclass."""
    def wrapper(cls):
        orig_vars = cls.__dict__.copy()
        slots = orig_vars.get("__slots__")
        if slots is not None:
            if isinstance(slots, str):
                slots = [slots]
            for slots_var in slots:
                orig_vars.pop(slots_var)
        orig_vars.pop("__dict__", None)
        orig_vars.pop("__weakref__", None)
        return metaclass(cls.__name__, cls.__bases__, orig_vars)
    return wrapper


@add_metaclass(ABCMeta)
class PEP247(object):
    @property
    @abstractmethod
    def digest_size(self):
        """The size of the digest produced by the hashing objects.
        """

    @abstractmethod
    def copy(self):
        """Return a separate copy of this hashing object.
        """

    @abstractmethod
    def update(self, data):
        """Hash data into the current state of the hashing object.
        """

    @abstractmethod
    def digest(self):
        """Return the hash value as a string containing 8-bit data.
        """

    def hexdigest(self):
        """Return the hash value as a string containing hexadecimal digits.
        """
        return hexenc(self.digest())
