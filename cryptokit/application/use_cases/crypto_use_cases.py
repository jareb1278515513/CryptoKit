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


def _with_trace(data: dict, enabled: bool, steps: list[str]) -> dict:
    """按需向返回数据注入执行轨迹。

    Args:
        data: 原始返回数据。
        enabled: 是否开启轨迹输出。
        steps: 轨迹步骤文本列表。

    Returns:
        dict: 最终返回数据。
    """
    if not enabled:
        return data
    payload = dict(data)
    payload["trace"] = steps
    return payload


def _encode_output(raw: bytes, output: str) -> str | bytes:
    """按指定格式编码二进制输出。

    Args:
        raw: 原始字节数据。
        output: 目标输出格式，支持 `raw`、`hex`、`base64`。

    Returns:
        str | bytes: 编码后的输出值。

    Raises:
        ValueError: 输出格式不在支持范围内时抛出。
    """
    mode = output.lower()
    if mode == "raw":
        return raw
    if mode == "hex":
        return raw.hex()
    if mode == "base64":
        return base64_encode(raw)
    raise ValueError("输出编码必须是 raw、hex 或 base64")


def _decode_input(payload: str, encoding: str) -> bytes:
    """按指定格式解码输入内容。

    Args:
        payload: 输入文本。
        encoding: 输入编码格式，支持 `utf8`、`hex`、`base64`。

    Returns:
        bytes: 解码后的字节串。

    Raises:
        ValueError: 输入编码格式不在支持范围内时抛出。
    """
    mode = encoding.lower()
    if mode == "utf8":
        return utf8_encode(payload)
    if mode == "hex":
        return bytes.fromhex(payload)
    if mode == "base64":
        return base64_decode(payload)
    raise ValueError("输入编码必须是 utf8、hex 或 base64")


def execute_utf8_encode(command: TextTransformCommand) -> OperationResult:
    """执行 UTF-8 编码用例。

    Args:
        command: 文本转换命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = utf8_encode(command.payload)
        return OperationResult.success(
            data=_with_trace(
                {"value": _encode_output(raw, command.output)},
                command.trace,
                [
                    "步骤1: 读取输入文本",
                    f"步骤2: 按 UTF-8 编码为字节流，长度={len(raw)}",
                    f"步骤3: 结果按 {command.output.lower()} 输出",
                ],
            )
        )
    except (EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def execute_utf8_decode(command: TextTransformCommand) -> OperationResult:
    """执行 UTF-8 解码用例。

    Args:
        command: 文本转换命令。

    Returns:
        OperationResult: 统一结果对象。
    """
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
    """执行 Base64 编码用例。

    Args:
        command: 文本转换命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        return OperationResult.success(data={"value": base64_encode(utf8_encode(command.payload))})
    except EncodingError as exc:
        return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def execute_base64_decode(command: TextTransformCommand) -> OperationResult:
    """执行 Base64 解码用例。

    Args:
        command: 文本转换命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        return OperationResult.success(data={"value": utf8_decode(base64_decode(command.payload))})
    except (EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def execute_hash(command: HashCommand) -> OperationResult:
    """执行消息摘要计算用例。

    Args:
        command: 哈希计算命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = digest(utf8_encode(command.payload), command.algorithm)
        return OperationResult.success(
            data=_with_trace(
                {
                    "algorithm": command.algorithm.lower(),
                    "supported_algorithms": sorted(SUPPORTED_DIGESTS),
                    "value": _encode_output(raw, command.output),
                },
                command.trace,
                [
                    "步骤1: 按 UTF-8 读取输入明文",
                    f"步骤2: 选择摘要算法 {command.algorithm.lower()}",
                    "步骤3: 计算消息摘要",
                    f"步骤4: 摘要按 {command.output.lower()} 输出",
                ],
            )
        )
    except (HashError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_hmac(command: HmacCommand) -> OperationResult:
    """执行 HMAC 计算用例。

    Args:
        command: HMAC 命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = hmac_digest(utf8_encode(command.payload), utf8_encode(command.key), command.algorithm)
        return OperationResult.success(
            data=_with_trace(
                {"algorithm": command.algorithm.lower(), "value": _encode_output(raw, command.output)},
                command.trace,
                [
                    "步骤1: 按 UTF-8 读取消息与密钥",
                    f"步骤2: 选择 HMAC 算法 {command.algorithm.lower()}",
                    "步骤3: 执行 HMAC 计算",
                    f"步骤4: 结果按 {command.output.lower()} 输出",
                ],
            )
        )
    except (HashError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_pbkdf2(command: Pbkdf2Command) -> OperationResult:
    """执行 PBKDF2 派生用例。

    Args:
        command: PBKDF2 命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = pbkdf2(
            password=utf8_encode(command.password),
            salt=utf8_encode(command.salt),
            iterations=command.iterations,
            dklen=command.dklen,
            algorithm=command.algorithm,
        )
        return OperationResult.success(
            data=_with_trace(
                {
                    "algorithm": command.algorithm.lower(),
                    "iterations": command.iterations,
                    "dklen": command.dklen,
                    "value": _encode_output(raw, command.output),
                },
                command.trace,
                [
                    "步骤1: 按 UTF-8 读取口令与盐值",
                    f"步骤2: 选择 PRF 哈希 {command.algorithm.lower()}",
                    f"步骤3: 执行 PBKDF2，迭代次数={command.iterations}，输出长度={command.dklen}",
                    f"步骤4: 派生结果按 {command.output.lower()} 输出",
                ],
            )
        )
    except (HashError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_symmetric_encrypt(command: SymmetricCommand) -> OperationResult:
    """执行对称加密用例。

    Args:
        command: 对称加密命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = _decode_input(command.payload, command.input_encoding)
    except (EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.INVALID_INPUT, f"输入错误: {exc}")

    try:
        key = bytes.fromhex(command.key_hex)
        iv = bytes.fromhex(command.iv_hex) if command.iv_hex else None
    except ValueError as exc:
        return OperationResult.failure(StatusCode.INVALID_KEY_SIZE, f"密钥或 IV 格式错误: {exc}")

    try:
        cipher = symmetric_encrypt(raw, key=key, algorithm=command.algorithm, mode=command.mode, iv=iv)
        return OperationResult.success(
            data=_with_trace(
                {
                    "algorithm": command.algorithm.lower(),
                    "mode": command.mode.lower(),
                    "value": _encode_output(cipher, command.output),
                },
                command.trace,
                [
                    f"步骤1: 读取输入并按 {command.input_encoding.lower()} 解码，明文长度={len(raw)}",
                    f"步骤2: 选择算法 {command.algorithm.lower()}，模式 {command.mode.lower()}",
                    f"步骤3: 校验密钥长度={len(key)} 字节",
                    "步骤4: 执行分组加密并完成必要填充",
                    f"步骤5: 密文按 {command.output.lower()} 输出",
                ],
            )
        )
    except SymmetricError as exc:
        message = str(exc)
        if "密钥" in message or "key" in message.lower():
            return OperationResult.failure(StatusCode.INVALID_KEY_SIZE, message)
        if "模式" in message or "mode" in message.lower():
            return OperationResult.failure(StatusCode.UNSUPPORTED_MODE, message)
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, message)
    except ValueError as exc:
        return OperationResult.failure(StatusCode.INVALID_INPUT, f"输入错误: {exc}")


def execute_symmetric_decrypt(command: SymmetricCommand) -> OperationResult:
    """执行对称解密用例。

    Args:
        command: 对称解密命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = _decode_input(command.payload, command.input_encoding)
    except (EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.INVALID_INPUT, f"输入错误: {exc}")

    try:
        key = bytes.fromhex(command.key_hex)
        iv = bytes.fromhex(command.iv_hex) if command.iv_hex else None
    except ValueError as exc:
        return OperationResult.failure(StatusCode.INVALID_KEY_SIZE, f"密钥或 IV 格式错误: {exc}")

    try:
        plain = symmetric_decrypt(raw, key=key, algorithm=command.algorithm, mode=command.mode, iv=iv)
        value = utf8_decode(plain) if command.output.lower() == "utf8" else _encode_output(plain, command.output)
        return OperationResult.success(
            data=_with_trace(
                {
                    "algorithm": command.algorithm.lower(),
                    "mode": command.mode.lower(),
                    "value": value,
                },
                command.trace,
                [
                    f"步骤1: 读取输入并按 {command.input_encoding.lower()} 解码，密文长度={len(raw)}",
                    f"步骤2: 选择算法 {command.algorithm.lower()}，模式 {command.mode.lower()}",
                    f"步骤3: 校验密钥长度={len(key)} 字节",
                    "步骤4: 执行分组解密并完成必要去填充",
                    f"步骤5: 明文按 {command.output.lower()} 输出",
                ],
            )
        )
    except SymmetricError as exc:
        message = str(exc)
        if "密钥" in message or "key" in message.lower():
            return OperationResult.failure(StatusCode.INVALID_KEY_SIZE, message)
        if "模式" in message or "mode" in message.lower():
            return OperationResult.failure(StatusCode.UNSUPPORTED_MODE, message)
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, message)
    except ValueError as exc:
        return OperationResult.failure(StatusCode.INVALID_INPUT, f"输入错误: {exc}")


def execute_rsa_keygen(command: RsaKeygenCommand) -> OperationResult:
    """执行 RSA 密钥对生成用例。

    Args:
        command: RSA 密钥生成命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        private_key_pem, public_key_pem = rsa_generate_keypair(bits=command.bits)
        return OperationResult.success(
            data=_with_trace(
                {
                    "algorithm": "rsa",
                    "bits": command.bits,
                    "private_key_pem": private_key_pem,
                    "public_key_pem": public_key_pem,
                },
                command.trace,
                [
                    f"步骤1: 选择 RSA 密钥长度 {command.bits}",
                    "步骤2: 生成 RSA 私钥",
                    "步骤3: 从私钥导出公钥",
                    "步骤4: 输出 PEM 格式密钥对",
                ],
            )
        )
    except (AsymmetricError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_rsa_encrypt(command: AsymmetricCryptoCommand) -> OperationResult:
    """执行 RSA 加密用例。

    Args:
        command: 公钥密码操作命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        cipher = rsa_encrypt(raw, public_key_pem=command.key_pem)
        return OperationResult.success(
            data=_with_trace(
                {"algorithm": "rsa", "value": _encode_output(cipher, command.output)},
                command.trace,
                [
                    f"步骤1: 读取明文并按 {command.input_encoding.lower()} 解码",
                    "步骤2: 加载 RSA 公钥",
                    "步骤3: 执行 RSA 加密",
                    f"步骤4: 密文按 {command.output.lower()} 输出",
                ],
            )
        )
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_rsa_decrypt(command: AsymmetricCryptoCommand) -> OperationResult:
    """执行 RSA 解密用例。

    Args:
        command: 公钥密码操作命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        plain = rsa_decrypt(raw, private_key_pem=command.key_pem)
        value = utf8_decode(plain) if command.output.lower() == "utf8" else _encode_output(plain, command.output)
        return OperationResult.success(
            data=_with_trace(
                {"algorithm": "rsa", "value": value},
                command.trace,
                [
                    f"步骤1: 读取密文并按 {command.input_encoding.lower()} 解码",
                    "步骤2: 加载 RSA 私钥",
                    "步骤3: 执行 RSA 解密",
                    f"步骤4: 明文按 {command.output.lower()} 输出",
                ],
            )
        )
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_rsa_sign(command: AsymmetricCryptoCommand) -> OperationResult:
    """执行 RSA-SHA1 签名用例。

    Args:
        command: 公钥密码操作命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        sig = rsa_sign_sha1(raw, private_key_pem=command.key_pem)
        return OperationResult.success(
            data=_with_trace(
                {"algorithm": "rsa-sha1", "value": _encode_output(sig, command.output)},
                command.trace,
                [
                    f"步骤1: 读取消息并按 {command.input_encoding.lower()} 解码",
                    "步骤2: 先计算 SHA-1 摘要",
                    "步骤3: 使用 RSA 私钥执行签名",
                    f"步骤4: 签名按 {command.output.lower()} 输出",
                ],
            )
        )
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_rsa_verify(command: VerifyCommand) -> OperationResult:
    """执行 RSA-SHA1 验签用例。

    Args:
        command: 验签命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        sig = _decode_input(command.signature, command.signature_encoding)
        ok = rsa_verify_sha1(raw, sig, public_key_pem=command.public_key_pem)
        return OperationResult.success(
            data=_with_trace(
                {"algorithm": "rsa-sha1", "verified": ok},
                command.trace,
                [
                    f"步骤1: 读取消息并按 {command.input_encoding.lower()} 解码",
                    f"步骤2: 读取签名并按 {command.signature_encoding.lower()} 解码",
                    "步骤3: 先计算 SHA-1 摘要",
                    "步骤4: 使用 RSA 公钥校验签名",
                ],
            )
        )
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_ecc_keygen(command: EccKeygenCommand) -> OperationResult:
    """执行 ECC 密钥对生成用例。

    Args:
        command: ECC 密钥生成命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    if command.curve.lower() != "nist-p160":
        return OperationResult.failure(StatusCode.INVALID_INPUT, "仅支持 nist-p160 曲线")
    try:
        private_key_pem, public_key_pem = ecc_generate_keypair_p160()
        return OperationResult.success(
            data=_with_trace(
                {
                    "algorithm": "ecc-160",
                    "curve": "nist-p160",
                    "private_key_pem": private_key_pem,
                    "public_key_pem": public_key_pem,
                },
                command.trace,
                [
                    "步骤1: 选择椭圆曲线 nist-p160",
                    "步骤2: 生成 ECC 私钥",
                    "步骤3: 从私钥导出公钥",
                    "步骤4: 输出 PEM 格式密钥对",
                ],
            )
        )
    except AsymmetricError as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_ecdsa_sign(command: AsymmetricCryptoCommand) -> OperationResult:
    """执行 ECDSA-SHA1 签名用例。

    Args:
        command: 公钥密码操作命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        sig = ecdsa_sign_sha1(raw, private_key_pem=command.key_pem)
        return OperationResult.success(
            data=_with_trace(
                {"algorithm": "ecdsa-sha1", "value": _encode_output(sig, command.output)},
                command.trace,
                [
                    f"步骤1: 读取消息并按 {command.input_encoding.lower()} 解码",
                    "步骤2: 先计算 SHA-1 摘要",
                    "步骤3: 使用 ECC 私钥执行 ECDSA 签名",
                    f"步骤4: 签名按 {command.output.lower()} 输出",
                ],
            )
        )
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def execute_ecdsa_verify(command: VerifyCommand) -> OperationResult:
    """执行 ECDSA-SHA1 验签用例。

    Args:
        command: 验签命令。

    Returns:
        OperationResult: 统一结果对象。
    """
    try:
        raw = _decode_input(command.payload, command.input_encoding)
        sig = _decode_input(command.signature, command.signature_encoding)
        ok = ecdsa_verify_sha1(raw, sig, public_key_pem=command.public_key_pem)
        return OperationResult.success(
            data=_with_trace(
                {"algorithm": "ecdsa-sha1", "verified": ok},
                command.trace,
                [
                    f"步骤1: 读取消息并按 {command.input_encoding.lower()} 解码",
                    f"步骤2: 读取签名并按 {command.signature_encoding.lower()} 解码",
                    "步骤3: 先计算 SHA-1 摘要",
                    "步骤4: 使用 ECC 公钥校验签名",
                ],
            )
        )
    except (AsymmetricError, EncodingError, ValueError) as exc:
        return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))
