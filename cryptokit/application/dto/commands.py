"""应用层输入命令对象。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class TextTransformCommand:
    """文本转换命令对象。

    Attributes:
        payload: 待处理的输入文本或编码串。
        input_encoding: 输入内容编码格式。
        output: 输出格式。
        trace: 是否返回执行轨迹。
    """

    payload: str
    input_encoding: str = "utf8"
    output: str = "hex"
    trace: bool = False


@dataclass(slots=True)
class HashCommand:
    """哈希计算命令对象。

    Attributes:
        payload: 待摘要的明文文本。
        algorithm: 摘要算法名称。
        output: 输出格式。
        trace: 是否返回执行轨迹。
    """

    payload: str
    algorithm: str = "sha256"
    output: str = "hex"
    trace: bool = False


@dataclass(slots=True)
class HmacCommand:
    """HMAC 计算命令对象。

    Attributes:
        payload: 待认证的消息文本。
        key: HMAC 密钥文本。
        algorithm: HMAC 所用哈希算法。
        output: 输出格式。
        trace: 是否返回执行轨迹。
    """

    payload: str
    key: str
    algorithm: str = "sha256"
    output: str = "hex"
    trace: bool = False


@dataclass(slots=True)
class Pbkdf2Command:
    """PBKDF2 派生命令对象。

    Attributes:
        password: 口令文本。
        salt: 盐值文本。
        iterations: 迭代次数。
        dklen: 派生密钥长度（字节）。
        algorithm: PRF 哈希算法。
        output: 输出格式。
        trace: 是否返回执行轨迹。
    """

    password: str
    salt: str
    iterations: int = 100000
    dklen: int = 32
    algorithm: str = "sha256"
    output: str = "hex"
    trace: bool = False


@dataclass(slots=True)
class SymmetricCommand:
    """对称加解密命令对象。

    Attributes:
        payload: 输入明文或密文。
        algorithm: 对称算法名称。
        mode: 分组模式。
        key_hex: 十六进制密钥。
        iv_hex: 十六进制 IV，可选。
        input_encoding: 输入编码。
        output: 输出编码。
        trace: 是否返回执行轨迹。
    """

    payload: str
    algorithm: str
    mode: str
    key_hex: str
    iv_hex: str | None = None
    input_encoding: str = "utf8"
    output: str = "hex"
    trace: bool = False


@dataclass(slots=True)
class RsaKeygenCommand:
    """RSA 密钥生成命令对象。

    Attributes:
        bits: 密钥位数。
        trace: 是否返回执行轨迹。
    """

    bits: int = 1024
    trace: bool = False


@dataclass(slots=True)
class EccKeygenCommand:
    """ECC 密钥生成命令对象。

    Attributes:
        curve: 椭圆曲线名称。
        trace: 是否返回执行轨迹。
    """

    curve: str = "nist-p160"
    trace: bool = False


@dataclass(slots=True)
class AsymmetricCryptoCommand:
    """公钥密码操作命令对象。

    Attributes:
        payload: 输入明文、密文或消息。
        key_pem: PEM 格式密钥文本。
        input_encoding: 输入编码。
        output: 输出编码。
        trace: 是否返回执行轨迹。
    """

    payload: str
    key_pem: str
    input_encoding: str = "utf8"
    output: str = "base64"
    trace: bool = False


@dataclass(slots=True)
class VerifyCommand:
    """签名验签命令对象。

    Attributes:
        payload: 待验签消息。
        signature: 签名文本。
        public_key_pem: PEM 格式公钥。
        input_encoding: 消息编码。
        signature_encoding: 签名编码。
        trace: 是否返回执行轨迹。
    """

    payload: str
    signature: str
    public_key_pem: str
    input_encoding: str = "utf8"
    signature_encoding: str = "base64"
    trace: bool = False
