from cryptokit.interfaces.api import (
    api_base64_decode,
    api_base64_encode,
    api_utf8_decode,
    api_utf8_encode,
)


def test_base64_round_trip() -> None:
    encoded = api_base64_encode("hello")
    assert encoded.ok
    assert encoded.data["value"] == "aGVsbG8="

    decoded = api_base64_decode(encoded.data["value"])
    assert decoded.ok
    assert decoded.data["value"] == "hello"


def test_utf8_encode_decode_hex() -> None:
    encoded = api_utf8_encode("密码学", output="hex")
    assert encoded.ok

    decoded = api_utf8_decode(encoded.data["value"], encoding="hex")
    assert decoded.ok
    assert decoded.data["value"] == "密码学"


def test_base64_decode_invalid_payload() -> None:
    result = api_base64_decode("***")
    assert not result.ok
    assert result.message
