"""应用层用例：编排编码、哈希、对称与公钥算法。"""

from __future__ import annotations

from cryptokit.application.dto.commands import (
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
from cryptokit.domain.asymmetric import (
    AsymmetricError,
    ecc_generate_keypair_p160,
    ecdsa_sign_sha1,
    ecdsa_verify_sha1,
    rsa_decrypt,
    rsa_encrypt,
    rsa_generate_keypair,
    rsa_sign_sha1,
    rsa_verify_sha1,
)
from cryptokit.domain.encoding import (
    EncodingError,
    base64_decode,
    base64_encode,
    utf8_decode,
    utf8_encode,
)
from cryptokit.domain.hash import HashError, SUPPORTED_DIGESTS, digest, hmac_digest, pbkdf2
from cryptokit.domain.symmetric import SymmetricError, symmetric_decrypt, symmetric_encrypt
from cryptokit.shared.errors import StatusCode
from cryptokit.shared.result import OperationResult


def _encode_output(raw: bytes, output: str) -> str | bytes:
    mode = output.lower()
    if mode == "raw":
        return raw
    if mode == "hex":
        return raw.hex()
    if mode == "base64":
        return base64_encode(raw)
    raise ValueError("输出编码必须是 raw、hex 或 base64")


def _decode_input(payload: str, encoding: str) -> bytes:
    mode = encoding.lower()
    if mode == "utf8":
        return utf8_encode(payload)
    if mode == "hex":
        return bytes.fromhex(payload)
    if mode == "base64":
        return base64_decode(payload)
    raise ValueError("输入编码必须是 utf8、hex 或 base64")


def execute_utf8_encode(command: TextTransformCommand) -> OperationResult:
    try:
        raw = utf8_encode(command.payload)
        return OperationResult.success(data={"value": _encode_output(raw, command.output)})
    except (EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def execute_utf8_decode(command: TextTransformCommand) -> OperationResult:
    try:
        mode = command.input_encoding.lower()
        if mode == "hex":
            raw = bytes.fromhex(command.payload)
        elif mode == "base64":
            raw = base64_decode(command.payload)
        else:
            return OperationResult.failure(StatusCode.INVALID_INPUT, "解码格式必须是 hex 或 base64")
        return OperationResult.success(data={"value": utf8_decode(raw)})
    except (EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def execute_base64_encode(command: TextTransformCommand) -> OperationResult:
    try:
        return OperationResult.success(data={"value": base64_encode(utf8_encode(command.payload))})
    except EncodingError as exc:
        return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def execute_base64_decode(command: TextTransformCommand) -> OperationResult:
    try:
        return OperationResult.success(data={"value": utf8_decode(base64_decode(command.payload))})
    except EncodingError as exc:
        return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def execute_hash(command: HashCommand) -> OperationResult:
    try:
        raw = digest(utf8_encode(command.payload), command.algorithm)
        return OperationResult.success(
            data={
                "algorithm": command.algorithm.lower(),
                "supported_algorithms": sorted(SUPPORTED_DIGESTS),
                "value": _encode_output(raw, command.output),
            }
        )
    except (HashError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_hmac(command: HmacCommand) -> OperationResult:
    try:
        raw = hmac_digest(utf8_encode(command.payload), utf8_encode(command.key), command.algorithm)
        return OperationResult.success(
            data={"algorithm": command.algorithm.lower(), "value": _encode_output(raw, command.output)}
        )
    except (HashError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_pbkdf2(command: Pbkdf2Command) -> OperationResult:
    try:
        raw = pbkdf2(
            password=utf8_encode(command.password),
            salt=utf8_encode(command.salt),
            iterations=command.iterations,
            dklen=command.dklen,
            algorithm=command.algorithm,
        )
        return OperationResult.success(
            data={
                "algorithm": command.algorithm.lower(),
                "iterations": command.iterations,
                "dklen": command.dklen,
                "value": _encode_output(raw, command.output),
            }
        )
    except (HashError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_symmetric_encrypt(command: SymmetricCommand) -> OperationResult:
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        key = bytes.fromhex(command.key_hex)
        iv = bytes.fromhex(command.iv_hex) if command.iv_hex else None
        cipher = symmetric_encrypt(raw, key=key, algorithm=command.algorithm, mode=command.mode, iv=iv)
        return OperationResult.success(
            data={
                "algorithm": command.algorithm.lower(),
                "mode": command.mode.lower(),
                "value": _encode_output(cipher, command.output),
            }
        )
    except (SymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_symmetric_decrypt(command: SymmetricCommand) -> OperationResult:
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        key = bytes.fromhex(command.key_hex)
        iv = bytes.fromhex(command.iv_hex) if command.iv_hex else None
        plain = symmetric_decrypt(raw, key=key, algorithm=command.algorithm, mode=command.mode, iv=iv)
        value = utf8_decode(plain) if command.output.lower() == "utf8" else _encode_output(plain, command.output)
        return OperationResult.success(
            data={
                "algorithm": command.algorithm.lower(),
                "mode": command.mode.lower(),
                "value": value,
            }
        )
    except (SymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_rsa_keygen(command: RsaKeygenCommand) -> OperationResult:
    try:
        private_key_pem, public_key_pem = rsa_generate_keypair(bits=command.bits)
        return OperationResult.success(
            data={
                "algorithm": "rsa",
                "bits": command.bits,
                "private_key_pem": private_key_pem,
                "public_key_pem": public_key_pem,
            }
        )
    except (AsymmetricError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_rsa_encrypt(command: AsymmetricCryptoCommand) -> OperationResult:
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        cipher = rsa_encrypt(raw, public_key_pem=command.key_pem)
        return OperationResult.success(data={"algorithm": "rsa", "value": _encode_output(cipher, command.output)})
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_rsa_decrypt(command: AsymmetricCryptoCommand) -> OperationResult:
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        plain = rsa_decrypt(raw, private_key_pem=command.key_pem)
        value = utf8_decode(plain) if command.output.lower() == "utf8" else _encode_output(plain, command.output)
        return OperationResult.success(data={"algorithm": "rsa", "value": value})
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_rsa_sign(command: AsymmetricCryptoCommand) -> OperationResult:
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        sig = rsa_sign_sha1(raw, private_key_pem=command.key_pem)
        return OperationResult.success(data={"algorithm": "rsa-sha1", "value": _encode_output(sig, command.output)})
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_rsa_verify(command: VerifyCommand) -> OperationResult:
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        sig = _decode_input(command.signature, command.signature_encoding)
        ok = rsa_verify_sha1(raw, sig, public_key_pem=command.public_key_pem)
        return OperationResult.success(data={"algorithm": "rsa-sha1", "verified": ok})
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_ecc_keygen(command: EccKeygenCommand) -> OperationResult:
    if command.curve.lower() != "nist-p160":
        return OperationResult.failure(StatusCode.INVALID_INPUT, "仅支持 nist-p160 曲线")
    try:
        private_key_pem, public_key_pem = ecc_generate_keypair_p160()
        return OperationResult.success(
            data={
                "algorithm": "ecc-160",
                "curve": "nist-p160",
                "private_key_pem": private_key_pem,
                "public_key_pem": public_key_pem,
            }
        )
    except AsymmetricError as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_ecdsa_sign(command: AsymmetricCryptoCommand) -> OperationResult:
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        sig = ecdsa_sign_sha1(raw, private_key_pem=command.key_pem)
        return OperationResult.success(data={"algorithm": "ecdsa-sha1", "value": _encode_output(sig, command.output)})
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_ecdsa_verify(command: VerifyCommand) -> OperationResult:
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        sig = _decode_input(command.signature, command.signature_encoding)
        ok = ecdsa_verify_sha1(raw, sig, public_key_pem=command.public_key_pem)
        return OperationResult.success(data={"algorithm": "ecdsa-sha1", "verified": ok})
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))
