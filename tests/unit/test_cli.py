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
