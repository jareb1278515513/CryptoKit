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
