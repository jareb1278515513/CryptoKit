"""公钥密码算法实现（RSA-1024 与 ECC-160/ECDSA）。"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from ecdsa import BadSignatureError, SECP160r1, SigningKey, VerifyingKey


class AsymmetricError(ValueError):
    """公钥密码相关操作失败时抛出。"""


def rsa_generate_keypair(bits: int = 1024) -> tuple[str, str]:
    """生成 RSA 密钥对并输出 PEM 文本。

    Args:
        bits: 密钥位数，仅支持 1024。

    Returns:
        tuple[str, str]: `(private_pem, public_pem)`。

    Raises:
        AsymmetricError: 参数不符合约束时抛出。
    """
    if bits != 1024:
        raise AsymmetricError("课程要求固定使用 RSA-1024")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def _load_rsa_public_key(public_key_pem: str):
    """加载并校验 RSA 公钥对象。

    Args:
        public_key_pem: PEM 格式公钥文本。

    Returns:
        rsa.RSAPublicKey: RSA 公钥对象。

    Raises:
        AsymmetricError: PEM 非法或密钥类型不匹配时抛出。
    """
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise AsymmetricError("RSA 公钥 PEM 格式无效") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise AsymmetricError("输入并非 RSA 公钥")
    return key


def _load_rsa_private_key(private_key_pem: str):
    """加载并校验 RSA 私钥对象。

    Args:
        private_key_pem: PEM 格式私钥文本。

    Returns:
        rsa.RSAPrivateKey: RSA 私钥对象。

    Raises:
        AsymmetricError: PEM 非法或密钥类型不匹配时抛出。
    """
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except Exception as exc:
        raise AsymmetricError("RSA 私钥 PEM 格式无效") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise AsymmetricError("输入并非 RSA 私钥")
    return key


def rsa_encrypt(raw: bytes, public_key_pem: str) -> bytes:
    """使用 RSA 公钥执行 PKCS#1 v1.5 加密。

    Args:
        raw: 明文字节串。
        public_key_pem: PEM 格式公钥文本。

    Returns:
        bytes: 密文字节串。

    Raises:
        AsymmetricError: 密钥加载或加密失败时抛出。
    """
    public_key = _load_rsa_public_key(public_key_pem)
    try:
        return public_key.encrypt(bytes(raw), padding.PKCS1v15())
    except Exception as exc:
        raise AsymmetricError("RSA 加密失败") from exc


def rsa_decrypt(raw: bytes, private_key_pem: str) -> bytes:
    """使用 RSA 私钥执行 PKCS#1 v1.5 解密。

    Args:
        raw: 密文字节串。
        private_key_pem: PEM 格式私钥文本。

    Returns:
        bytes: 明文字节串。

    Raises:
        AsymmetricError: 密钥加载或解密失败时抛出。
    """
    private_key = _load_rsa_private_key(private_key_pem)
    try:
        return private_key.decrypt(bytes(raw), padding.PKCS1v15())
    except Exception as exc:
        raise AsymmetricError("RSA 解密失败") from exc


def rsa_sign_sha1(raw: bytes, private_key_pem: str) -> bytes:
    """使用 RSA 私钥执行 SHA1withRSA 签名。

    Args:
        raw: 待签名消息字节串。
        private_key_pem: PEM 格式私钥文本。

    Returns:
        bytes: 签名字节串。

    Raises:
        AsymmetricError: 密钥加载或签名失败时抛出。
    """
    private_key = _load_rsa_private_key(private_key_pem)
    try:
        return private_key.sign(bytes(raw), padding.PKCS1v15(), hashes.SHA1())
    except Exception as exc:
        raise AsymmetricError("RSA-SHA1 签名失败") from exc


def rsa_verify_sha1(raw: bytes, signature: bytes, public_key_pem: str) -> bool:
    """使用 RSA 公钥验证 SHA1withRSA 签名。

    Args:
        raw: 待验签消息字节串。
        signature: 签名字节串。
        public_key_pem: PEM 格式公钥文本。

    Returns:
        bool: 验签是否通过。
    """
    public_key = _load_rsa_public_key(public_key_pem)
    try:
        public_key.verify(bytes(signature), bytes(raw), padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception:
        return False


def ecc_generate_keypair_p160() -> tuple[str, str]:
    """生成 NIST P-160 椭圆曲线密钥对。

    Returns:
        tuple[str, str]: `(private_pem, public_pem)`。
    """
    sk = SigningKey.generate(curve=SECP160r1)
    vk = sk.get_verifying_key()
    return sk.to_pem().decode("utf-8"), vk.to_pem().decode("utf-8")


def _load_ecc_private_key(private_key_pem: str) -> SigningKey:
    """加载并校验 ECC 私钥。

    Args:
        private_key_pem: PEM 格式私钥文本。

    Returns:
        SigningKey: ECC 私钥对象。

    Raises:
        AsymmetricError: PEM 非法时抛出。
    """
    try:
        return SigningKey.from_pem(private_key_pem)
    except Exception as exc:
        raise AsymmetricError("ECC-160 私钥 PEM 格式无效") from exc


def _load_ecc_public_key(public_key_pem: str) -> VerifyingKey:
    """加载并校验 ECC 公钥。

    Args:
        public_key_pem: PEM 格式公钥文本。

    Returns:
        VerifyingKey: ECC 公钥对象。

    Raises:
        AsymmetricError: PEM 非法时抛出。
    """
    try:
        return VerifyingKey.from_pem(public_key_pem)
    except Exception as exc:
        raise AsymmetricError("ECC-160 公钥 PEM 格式无效") from exc


def ecdsa_sign_sha1(raw: bytes, private_key_pem: str) -> bytes:
    """使用 ECC 私钥执行 ECDSA-SHA1 签名。

    Args:
        raw: 待签名消息字节串。
        private_key_pem: PEM 格式私钥文本。

    Returns:
        bytes: 签名字节串。

    Raises:
        AsymmetricError: 密钥加载或签名失败时抛出。
    """
    sk = _load_ecc_private_key(private_key_pem)
    try:
        return sk.sign(bytes(raw), hashfunc=__import__("hashlib").sha1)
    except Exception as exc:
        raise AsymmetricError("ECDSA-SHA1 签名失败") from exc


def ecdsa_verify_sha1(raw: bytes, signature: bytes, public_key_pem: str) -> bool:
    """使用 ECC 公钥验证 ECDSA-SHA1 签名。

    Args:
        raw: 待验签消息字节串。
        signature: 签名字节串。
        public_key_pem: PEM 格式公钥文本。

    Returns:
        bool: 验签是否通过。
    """
    vk = _load_ecc_public_key(public_key_pem)
    try:
        return vk.verify(bytes(signature), bytes(raw), hashfunc=__import__("hashlib").sha1)
    except BadSignatureError:
        return False
    except Exception:
        return False
