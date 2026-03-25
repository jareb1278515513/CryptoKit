"""应用层输入命令对象。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class TextTransformCommand:
    payload: str
    input_encoding: str = "utf8"
    output: str = "hex"


@dataclass(slots=True)
class HashCommand:
    payload: str
    algorithm: str = "sha256"
    output: str = "hex"


@dataclass(slots=True)
class HmacCommand:
    payload: str
    key: str
    algorithm: str = "sha256"
    output: str = "hex"


@dataclass(slots=True)
class Pbkdf2Command:
    password: str
    salt: str
    iterations: int = 100000
    dklen: int = 32
    algorithm: str = "sha256"
    output: str = "hex"


@dataclass(slots=True)
class SymmetricCommand:
    payload: str
    algorithm: str
    mode: str
    key_hex: str
    iv_hex: str | None = None
    input_encoding: str = "utf8"
    output: str = "hex"


@dataclass(slots=True)
class RsaKeygenCommand:
    bits: int = 1024


@dataclass(slots=True)
class EccKeygenCommand:
    curve: str = "nist-p160"


@dataclass(slots=True)
class AsymmetricCryptoCommand:
    payload: str
    key_pem: str
    input_encoding: str = "utf8"
    output: str = "base64"


@dataclass(slots=True)
class VerifyCommand:
    payload: str
    signature: str
    public_key_pem: str
    input_encoding: str = "utf8"
    signature_encoding: str = "base64"
