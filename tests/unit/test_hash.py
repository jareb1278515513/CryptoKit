from cryptokit.interfaces.api import api_hash_text, api_hmac_text, api_pbkdf2


def test_sha256_hash_vector() -> None:
    result = api_hash_text("abc", algorithm="sha256", output="hex")
    assert result.ok
    assert (
        result.data["value"]
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_hmac_sha1_vector() -> None:
    result = api_hmac_text("The quick brown fox", key="key", algorithm="sha1", output="hex")
    assert result.ok
    assert result.data["value"] == "22f9e077a3cebd09248154f85d9a56c79941fd96"


def test_pbkdf2_deterministic() -> None:
    result = api_pbkdf2(
        "password",
        salt="salt",
        iterations=1,
        dklen=20,
        algorithm="sha1",
        output="hex",
    )
    assert result.ok
    assert result.data["value"] == "0c60c80f961f0e71f3a9b524af6012062fe037a6"


def test_unsupported_digest() -> None:
    result = api_hash_text("abc", algorithm="md5")
    assert not result.ok
