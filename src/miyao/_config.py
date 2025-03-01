from __future__ import annotations

from joserfc.jwk import OctKey

from ._vault import DEFAULT_ALGORITHM
from ._vault import DEFAULT_ENCRYPTION
from ._vault import Algorithms
from ._vault import Encryptions
from ._vault import import_key

__all__ = [
    "UserConfig",
]


class UserConfig:
    raw_key: str | None = None
    algorithm: Algorithms = DEFAULT_ALGORITHM
    encryption: Encryptions = DEFAULT_ENCRYPTION

    @property
    def key(self) -> OctKey | None:
        if self.raw_key is None:
            return None
        return import_key(self.raw_key, self.algorithm)

    @classmethod
    def load_config(cls):
        pass
