import json

from cryptokit.interfaces.cli import run_cli


def test_cli_rsa_end_to_end(capsys) -> None:
    gen_code = run_cli(["rsa-generate"])
    gen_result = json.loads(capsys.readouterr().out)
    assert gen_code == 0

    pri = gen_result["data"]["private_key_pem"]
    pub = gen_result["data"]["public_key_pem"]

    sign_code = run_cli(["rsa-sign", "--payload", "hello", "--private-key-pem", pri])
    sign_result = json.loads(capsys.readouterr().out)
    assert sign_code == 0

    verify_code = run_cli(
        [
            "rsa-verify",
            "--payload",
            "hello",
            "--signature",
            sign_result["data"]["value"],
            "--public-key-pem",
            pub,
        ]
    )
    verify_result = json.loads(capsys.readouterr().out)
    assert verify_code == 0
    assert verify_result["data"]["verified"] is True
