import pytest

from cryptokit.domain.symmetric import SymmetricError, symmetric_decrypt, symmetric_encrypt
from cryptokit.interfaces.api import api_symmetric_decrypt, api_symmetric_encrypt


def test_aes_ecb_encrypt_decrypt_roundtrip() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = symmetric_encrypt(b"hello-aes", key=key, algorithm="aes", mode="ecb")
    plain = symmetric_decrypt(cipher, key=key, algorithm="aes", mode="ecb")
    assert plain == b"hello-aes"


def test_aes_cbc_nist_vector() -> None:
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")

    cipher = symmetric_encrypt(plain, key=key, algorithm="aes", mode="cbc", iv=iv)
    assert cipher[:16] == expected

    restored = symmetric_decrypt(cipher, key=key, algorithm="aes", mode="cbc", iv=iv)
    assert restored == plain


def test_sm4_ecb_vector() -> None:
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    plain = bytes.fromhex("0123456789abcdeffedcba9876543210")
    result = symmetric_encrypt(plain, key=key, algorithm="sm4", mode="ecb")
    assert result[:16] == bytes.fromhex("681edf34d206965e86b3e94f536e4246")


def test_rc6_ecb_vector() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    result = symmetric_encrypt(plain, key=key, algorithm="rc6", mode="ecb")
    assert result[:16] == bytes.fromhex("3a96f9c7f6755cfe46f00e3dcd5d2a3c")


def test_api_symmetric_encrypt_decrypt_roundtrip() -> None:
    key_hex = "00112233445566778899aabbccddeeff"
    enc = api_symmetric_encrypt(
        "hello-rc6",
        algorithm="rc6",
        mode="cbc",
        key_hex=key_hex,
        iv_hex="000102030405060708090a0b0c0d0e0f",
        output="hex",
    )
    assert enc.ok

    dec = api_symmetric_decrypt(
        enc.data["value"],
        algorithm="rc6",
        mode="cbc",
        key_hex=key_hex,
        iv_hex="000102030405060708090a0b0c0d0e0f",
        input_encoding="hex",
        output="utf8",
    )
    assert dec.ok
    assert dec.data["value"] == "hello-rc6"


def test_missing_iv_for_cbc() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    with pytest.raises(SymmetricError):
        symmetric_encrypt(b"payload", key=key, algorithm="aes", mode="cbc")
