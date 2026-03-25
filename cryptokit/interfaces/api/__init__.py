"""Python API 适配层。"""

from __future__ import annotations

from cryptokit.application.dto import (
    AsymmetricCryptoCommand,
    EccKeygenCommand,
    HashCommand,
    HmacCommand,
    Pbkdf2Command,
    RsaKeygenCommand,
    SymmetricCommand,
    TextTransformCommand,
    VerifyCommand,
)
from cryptokit.application.use_cases import (
    execute_base64_decode,
    execute_base64_encode,
    execute_ecc_keygen,
    execute_ecdsa_sign,
    execute_ecdsa_verify,
    execute_hash,
    execute_hmac,
    execute_pbkdf2,
    execute_rsa_decrypt,
    execute_rsa_encrypt,
    execute_rsa_keygen,
    execute_rsa_sign,
    execute_rsa_verify,
    execute_symmetric_decrypt,
    execute_symmetric_encrypt,
    execute_utf8_decode,
    execute_utf8_encode,
)
from cryptokit.shared.result import OperationResult


def api_utf8_encode(text: str, output: str = "hex", trace: bool = False) -> OperationResult:
    return execute_utf8_encode(TextTransformCommand(payload=text, output=output, trace=trace))


def api_utf8_decode(hex_or_base64_payload: str, encoding: str = "hex", trace: bool = False) -> OperationResult:
    return execute_utf8_decode(
        TextTransformCommand(payload=hex_or_base64_payload, input_encoding=encoding, trace=trace)
    )


def api_base64_encode(text: str, trace: bool = False) -> OperationResult:
    return execute_base64_encode(TextTransformCommand(payload=text, trace=trace))


def api_base64_decode(payload: str, trace: bool = False) -> OperationResult:
    return execute_base64_decode(TextTransformCommand(payload=payload, trace=trace))


def api_hash_text(text: str, algorithm: str = "sha256", output: str = "hex", trace: bool = False) -> OperationResult:
    return execute_hash(HashCommand(payload=text, algorithm=algorithm, output=output, trace=trace))


def api_hmac_text(
    text: str,
    key: str,
    algorithm: str = "sha256",
    output: str = "hex",
    trace: bool = False,
) -> OperationResult:
    return execute_hmac(HmacCommand(payload=text, key=key, algorithm=algorithm, output=output, trace=trace))


def api_pbkdf2(
    password: str,
    salt: str,
    iterations: int = 100000,
    dklen: int = 32,
    algorithm: str = "sha256",
    output: str = "hex",
    trace: bool = False,
) -> OperationResult:
    return execute_pbkdf2(
        Pbkdf2Command(
            password=password,
            salt=salt,
            iterations=iterations,
            dklen=dklen,
            algorithm=algorithm,
            output=output,
            trace=trace,
        )
    )


def api_symmetric_encrypt(
    payload: str,
    *,
    algorithm: str,
    mode: str,
    key_hex: str,
    iv_hex: str | None = None,
    input_encoding: str = "utf8",
    output: str = "hex",
    trace: bool = False,
) -> OperationResult:
    return execute_symmetric_encrypt(
        SymmetricCommand(
            payload=payload,
            algorithm=algorithm,
            mode=mode,
            key_hex=key_hex,
            iv_hex=iv_hex,
            input_encoding=input_encoding,
            output=output,
            trace=trace,
        )
    )


def api_symmetric_decrypt(
    payload: str,
    *,
    algorithm: str,
    mode: str,
    key_hex: str,
    iv_hex: str | None = None,
    input_encoding: str = "hex",
    output: str = "utf8",
    trace: bool = False,
) -> OperationResult:
    return execute_symmetric_decrypt(
        SymmetricCommand(
            payload=payload,
            algorithm=algorithm,
            mode=mode,
            key_hex=key_hex,
            iv_hex=iv_hex,
            input_encoding=input_encoding,
            output=output,
            trace=trace,
        )
    )


def api_rsa_generate_keypair(bits: int = 1024, trace: bool = False) -> OperationResult:
    return execute_rsa_keygen(RsaKeygenCommand(bits=bits, trace=trace))


def api_rsa_encrypt(
    payload: str,
    *,
    public_key_pem: str,
    input_encoding: str = "utf8",
    output: str = "base64",
    trace: bool = False,
) -> OperationResult:
    return execute_rsa_encrypt(
        AsymmetricCryptoCommand(
            payload=payload,
            key_pem=public_key_pem,
            input_encoding=input_encoding,
            output=output,
            trace=trace,
        )
    )


def api_rsa_decrypt(
    payload: str,
    *,
    private_key_pem: str,
    input_encoding: str = "base64",
    output: str = "utf8",
    trace: bool = False,
) -> OperationResult:
    return execute_rsa_decrypt(
        AsymmetricCryptoCommand(
            payload=payload,
            key_pem=private_key_pem,
            input_encoding=input_encoding,
            output=output,
            trace=trace,
        )
    )


def api_rsa_sign_sha1(
    payload: str,
    *,
    private_key_pem: str,
    input_encoding: str = "utf8",
    output: str = "base64",
    trace: bool = False,
) -> OperationResult:
    return execute_rsa_sign(
        AsymmetricCryptoCommand(
            payload=payload,
            key_pem=private_key_pem,
            input_encoding=input_encoding,
            output=output,
            trace=trace,
        )
    )


def api_rsa_verify_sha1(
    payload: str,
    *,
    signature: str,
    public_key_pem: str,
    input_encoding: str = "utf8",
    signature_encoding: str = "base64",
    trace: bool = False,
) -> OperationResult:
    return execute_rsa_verify(
        VerifyCommand(
            payload=payload,
            signature=signature,
            public_key_pem=public_key_pem,
            input_encoding=input_encoding,
            signature_encoding=signature_encoding,
            trace=trace,
        )
    )


def api_ecc_generate_keypair(trace: bool = False) -> OperationResult:
    return execute_ecc_keygen(EccKeygenCommand(curve="nist-p160", trace=trace))


def api_ecdsa_sign_sha1(
    payload: str,
    *,
    private_key_pem: str,
    input_encoding: str = "utf8",
    output: str = "base64",
    trace: bool = False,
) -> OperationResult:
    return execute_ecdsa_sign(
        AsymmetricCryptoCommand(
            payload=payload,
            key_pem=private_key_pem,
            input_encoding=input_encoding,
            output=output,
            trace=trace,
        )
    )


def api_ecdsa_verify_sha1(
    payload: str,
    *,
    signature: str,
    public_key_pem: str,
    input_encoding: str = "utf8",
    signature_encoding: str = "base64",
    trace: bool = False,
) -> OperationResult:
    return execute_ecdsa_verify(
        VerifyCommand(
            payload=payload,
            signature=signature,
            public_key_pem=public_key_pem,
            input_encoding=input_encoding,
            signature_encoding=signature_encoding,
            trace=trace,
        )
    )


__all__ = [
    "api_utf8_encode",
    "api_utf8_decode",
    "api_base64_encode",
    "api_base64_decode",
    "api_hash_text",
    "api_hmac_text",
    "api_pbkdf2",
    "api_symmetric_encrypt",
    "api_symmetric_decrypt",
    "api_rsa_generate_keypair",
    "api_rsa_encrypt",
    "api_rsa_decrypt",
    "api_rsa_sign_sha1",
    "api_rsa_verify_sha1",
    "api_ecc_generate_keypair",
    "api_ecdsa_sign_sha1",
    "api_ecdsa_verify_sha1",
]
