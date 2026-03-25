import json

from cryptokit.interfaces.api import api_symmetric_encrypt
from cryptokit.interfaces.cli import run_cli


def test_error_code_invalid_input_api() -> None:
    result = api_symmetric_encrypt(
        "zz",
        algorithm="aes",
        mode="cbc",
        key_hex="00112233445566778899aabbccddeeff",
        iv_hex="000102030405060708090a0b0c0d0e0f",
        input_encoding="hex",
        output="hex",
    )
    assert int(result.code) == 400


def test_error_code_invalid_key_api() -> None:
    result = api_symmetric_encrypt(
        "hello",
        algorithm="aes",
        mode="cbc",
        key_hex="0011",
        iv_hex="000102030405060708090a0b0c0d0e0f",
        output="hex",
    )
    assert int(result.code) == 401


def test_error_code_unsupported_mode_api() -> None:
    result = api_symmetric_encrypt(
        "hello",
        algorithm="aes",
        mode="gcm",
        key_hex="00112233445566778899aabbccddeeff",
        iv_hex="000102030405060708090a0b0c0d0e0f",
        output="hex",
    )
    assert int(result.code) == 402


def test_error_code_invalid_key_cli(capsys) -> None:
    code = run_cli(
        [
            "symmetric-encrypt",
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--payload",
            "hello",
            "--key-hex",
            "0011",
            "--iv-hex",
            "000102030405060708090a0b0c0d0e0f",
            "--output",
            "hex",
        ]
    )
    output = capsys.readouterr().out
    data = json.loads(output)
    assert code == 1
    assert data["code"] == 401
