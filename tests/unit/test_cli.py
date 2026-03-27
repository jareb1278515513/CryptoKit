import json

from cryptokit.infrastructure import key_io
from cryptokit.interfaces.cli import run_cli


def test_cli_hash_command(capsys) -> None:
    code = run_cli(["hash", "--text", "abc", "--algorithm", "sha256"])
    captured = capsys.readouterr()
    assert code == 0
    assert '"code": 200' in captured.out


def test_cli_invalid_base64(capsys) -> None:
    code = run_cli(["base64-decode", "--payload", "***"])
    captured = capsys.readouterr()
    assert code == 1
    assert '"code": 501' in captured.out


def test_cli_symmetric_encrypt_decrypt(capsys) -> None:
    key_hex = "00112233445566778899aabbccddeeff"
    iv_hex = "000102030405060708090a0b0c0d0e0f"

    encrypt_code = run_cli(
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
    encrypted_output = capsys.readouterr().out
    assert encrypt_code == 0
    cipher_hex = encrypted_output.split('"value": "')[1].split('"')[0]

    decrypt_code = run_cli(
        [
            "symmetric-decrypt",
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--payload",
            cipher_hex,
            "--key-hex",
            key_hex,
            "--iv-hex",
            iv_hex,
            "--input-encoding",
            "hex",
            "--output",
            "utf8",
        ]
    )
    decrypted_output = capsys.readouterr().out
    assert decrypt_code == 0
    assert '"value": "hello"' in decrypted_output


def test_cli_rsa_sign_verify(capsys) -> None:
    gen_code = run_cli(["rsa-generate"])
    gen_output = capsys.readouterr().out
    assert gen_code == 0
    keys = json.loads(gen_output)["data"]

    sign_code = run_cli(
        [
            "rsa-sign",
            "--payload",
            "hello",
            "--private-key-pem",
            keys["private_key_pem"],
        ]
    )
    sign_output = capsys.readouterr().out
    assert sign_code == 0
    signature = json.loads(sign_output)["data"]["value"]

    verify_code = run_cli(
        [
            "rsa-verify",
            "--payload",
            "hello",
            "--signature",
            signature,
            "--public-key-pem",
            keys["public_key_pem"],
        ]
    )
    verify_output = capsys.readouterr().out
    assert verify_code == 0
    assert '"verified": true' in verify_output


def test_cli_rsa_generate_saves_default_keyfiles(capsys, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(key_io, "DEFAULT_KEYFILES_ROOT", tmp_path / "keyfiles")

    code = run_cli(["rsa-generate", "--bits", "1024"])
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    private_key_file = tmp_path / "keyfiles" / "rsa" / "rsa_pri.pem"
    public_key_file = tmp_path / "keyfiles" / "rsa" / "rsa_pub.pem"
    assert private_key_file.exists()
    assert public_key_file.exists()
    assert result["data"]["private_key_file"] == str(private_key_file)
    assert result["data"]["public_key_file"] == str(public_key_file)


def test_cli_rsa_encrypt_uses_default_keyfiles(capsys, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(key_io, "DEFAULT_KEYFILES_ROOT", tmp_path / "keyfiles")

    gen_code = run_cli(["rsa-generate", "--bits", "1024"])
    assert gen_code == 0
    capsys.readouterr()

    encrypt_code = run_cli(
        [
            "rsa-encrypt",
            "--payload",
            "hello-rsa",
            "--input-encoding",
            "utf8",
            "--output",
            "base64",
        ]
    )
    encrypt_result = json.loads(capsys.readouterr().out)

    assert encrypt_code == 0
    assert encrypt_result["code"] == 200
    assert encrypt_result["data"]["algorithm"] == "rsa"
