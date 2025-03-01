from __future__ import annotations

import json
from pathlib import Path

from joserfc.jwk import OctKey

from ._vault import DEFAULT_ALGORITHM
from ._vault import DEFAULT_ENCRYPTION
from ._vault import AlgorithmTypes
from ._vault import EncryptionTypes
from ._vault import decrypt
from ._vault import import_key
from ._vault import parse_content

__all__ = [
    "UserConfig",
    "parse_config",
]


class UserConfig:
    raw_key: str | None = None
    algorithm: AlgorithmTypes = DEFAULT_ALGORITHM
    encryption: EncryptionTypes = DEFAULT_ENCRYPTION

    @property
    def key(self) -> OctKey | None:
        if self.raw_key is None:
            return None
        return import_key(self.raw_key, self.algorithm)

    @classmethod
    def create(cls):
        obj = cls()
        file_path = Path.home() / ".config" / "miyao.json"
        if file_path.exists():
            with open(file_path) as f:
                data = json.load(f)
            if "key" in data:
                obj.raw_key = data["key"]
            if "algorithm" in data:
                obj.algorithm = data["algorithm"]
            if "encryption" in data:
                obj.encryptions = data["encryption"]
        return obj


def parse_config(filename: str, key: str, algorithm: AlgorithmTypes = DEFAULT_ALGORITHM) -> dict[str, str]:
    file_path = Path(filename)
    if file_path.exists():
        _key = import_key(key, algorithm)
        with open(file_path) as f:
            decrypted = decrypt(f.read(), _key)
            data = parse_content(decrypted)
    else:
        data = {}
    return data
