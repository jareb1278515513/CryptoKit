"""密钥序列化与读写适配器。"""

from __future__ import annotations

from pathlib import Path


DEFAULT_KEYFILES_ROOT = Path(__file__).resolve().parents[3] / "keyfiles"
_KEY_FILENAMES = {
    "rsa": {
        "private": "rsa_pri.pem",
        "public": "rsa_pub.pem",
    },
    "ecc": {
        "private": "ecc_pri.pem",
        "public": "ecc_pub.pem",
    },
}


def get_algorithm_key_dir(algorithm: str) -> Path:
    """返回算法对应的默认密钥目录。"""
    return DEFAULT_KEYFILES_ROOT / algorithm.lower()


def get_default_key_path(algorithm: str, key_kind: str) -> Path:
    """返回算法默认密钥文件路径。"""
    algorithm_name = algorithm.lower()
    if algorithm_name not in _KEY_FILENAMES:
        raise ValueError(f"不支持的算法: {algorithm}")
    if key_kind not in _KEY_FILENAMES[algorithm_name]:
        raise ValueError(f"不支持的密钥类型: {key_kind}")
    return get_algorithm_key_dir(algorithm_name) / _KEY_FILENAMES[algorithm_name][key_kind]


def read_key_text(path: str | Path) -> str:
    """读取 PEM 文本内容。"""
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"读取密钥文件失败: {path}") from exc


def save_keypair(algorithm: str, private_key_pem: str, public_key_pem: str) -> dict[str, str]:
    """将密钥对保存到默认目录。"""
    algorithm_dir = get_algorithm_key_dir(algorithm)
    algorithm_dir.mkdir(parents=True, exist_ok=True)

    private_key_path = get_default_key_path(algorithm, "private")
    public_key_path = get_default_key_path(algorithm, "public")
    private_key_path.write_text(private_key_pem, encoding="utf-8")
    public_key_path.write_text(public_key_pem, encoding="utf-8")

    return {
        "private_key_file": str(private_key_path),
        "public_key_file": str(public_key_path),
    }


__all__ = [
    "DEFAULT_KEYFILES_ROOT",
    "get_algorithm_key_dir",
    "get_default_key_path",
    "read_key_text",
    "save_keypair",
]
