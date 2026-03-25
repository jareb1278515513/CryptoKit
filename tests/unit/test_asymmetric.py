from cryptokit.domain.asymmetric import (
    ecc_generate_keypair_p160,
    ecdsa_sign_sha1,
    ecdsa_verify_sha1,
    rsa_decrypt,
    rsa_encrypt,
    rsa_generate_keypair,
    rsa_sign_sha1,
    rsa_verify_sha1,
)
from cryptokit.interfaces.api import (
    api_ecc_generate_keypair,
    api_ecdsa_sign_sha1,
    api_ecdsa_verify_sha1,
    api_rsa_decrypt,
    api_rsa_encrypt,
    api_rsa_generate_keypair,
    api_rsa_sign_sha1,
    api_rsa_verify_sha1,
)


def test_rsa_encrypt_decrypt_roundtrip() -> None:
    private_key_pem, public_key_pem = rsa_generate_keypair()
    cipher = rsa_encrypt(b"hello-rsa", public_key_pem)
    plain = rsa_decrypt(cipher, private_key_pem)
    assert plain == b"hello-rsa"


def test_rsa_sha1_sign_verify() -> None:
    private_key_pem, public_key_pem = rsa_generate_keypair()
    message = b"rsa-sign"
    signature = rsa_sign_sha1(message, private_key_pem)
    assert rsa_verify_sha1(message, signature, public_key_pem)
    assert not rsa_verify_sha1(b"bad", signature, public_key_pem)


def test_ecc_ecdsa_sha1_sign_verify() -> None:
    private_key_pem, public_key_pem = ecc_generate_keypair_p160()
    message = b"ecdsa-sign"
    signature = ecdsa_sign_sha1(message, private_key_pem)
    assert ecdsa_verify_sha1(message, signature, public_key_pem)
    assert not ecdsa_verify_sha1(b"bad", signature, public_key_pem)


def test_api_rsa_flow() -> None:
    keys = api_rsa_generate_keypair()
    assert keys.ok

    private_key_pem = keys.data["private_key_pem"]
    public_key_pem = keys.data["public_key_pem"]

    enc = api_rsa_encrypt("hello", public_key_pem=public_key_pem)
    assert enc.ok

    dec = api_rsa_decrypt(enc.data["value"], private_key_pem=private_key_pem)
    assert dec.ok
    assert dec.data["value"] == "hello"

    sign = api_rsa_sign_sha1("hello", private_key_pem=private_key_pem)
    assert sign.ok

    verify = api_rsa_verify_sha1(
        "hello",
        signature=sign.data["value"],
        public_key_pem=public_key_pem,
    )
    assert verify.ok
    assert verify.data["verified"] is True


def test_api_ecc_flow() -> None:
    keys = api_ecc_generate_keypair()
    assert keys.ok

    private_key_pem = keys.data["private_key_pem"]
    public_key_pem = keys.data["public_key_pem"]

    sign = api_ecdsa_sign_sha1("hello", private_key_pem=private_key_pem)
    assert sign.ok

    verify = api_ecdsa_verify_sha1(
        "hello",
        signature=sign.data["value"],
        public_key_pem=public_key_pem,
    )
    assert verify.ok
    assert verify.data["verified"] is True
