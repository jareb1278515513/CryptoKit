import json

from cryptokit.interfaces.cli import run_cli


def test_cli_hash_trace_output(capsys) -> None:
    code = run_cli(["--trace", "hash", "--text", "hello", "--algorithm", "sha256"])
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert "trace" in result["data"]
    assert len(result["data"]["trace"]) >= 3
    assert "sha256" in "\n".join(result["data"]["trace"]).lower()
