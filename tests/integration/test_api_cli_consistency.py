import json

from cryptokit.interfaces.api import api_hash_text, api_symmetric_encrypt
from cryptokit.interfaces.cli import run_cli


def test_hash_api_cli_consistency(capsys) -> None:
    api_result = api_hash_text("abc", algorithm="sha256", output="hex")
    assert api_result.ok

    cli_code = run_cli(["hash", "--text", "abc", "--algorithm", "sha256", "--output", "hex"])
    cli_output = capsys.readouterr().out
    assert cli_code == 0
    cli_result = json.loads(cli_output)

    assert cli_result["data"]["value"] == api_result.data["value"]


def test_symmetric_api_cli_consistency(capsys) -> None:
    key_hex = "00112233445566778899aabbccddeeff"
    iv_hex = "000102030405060708090a0b0c0d0e0f"

    api_result = api_symmetric_encrypt(
        "hello",
        algorithm="aes",
        mode="cbc",
        key_hex=key_hex,
        iv_hex=iv_hex,
        output="hex",
    )
    assert api_result.ok

    cli_code = run_cli(
        [
            "symmetric-encrypt",
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--payload",
            "hello",
            "--key-hex",
            key_hex,
            "--iv-hex",
            iv_hex,
            "--output",
            "hex",
        ]
    )
    cli_output = capsys.readouterr().out
    assert cli_code == 0
    cli_result = json.loads(cli_output)

    assert cli_result["data"]["value"] == api_result.data["value"]
