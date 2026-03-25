import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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


def show(name, result):
    payload = result.to_dict()
    print(f"[{name}] {json.dumps(payload, ensure_ascii=False)}")
    return payload


if __name__ == "__main__":
    rsa_gen = show("RSA密钥生成", api_rsa_generate_keypair(bits=1024, trace=True))
    if rsa_gen["code"] == 200:
        pri = rsa_gen["data"]["private_key_pem"]
        pub = rsa_gen["data"]["public_key_pem"]

        rsa_enc = show("RSA加密", api_rsa_encrypt("hello", public_key_pem=pub, output="base64"))
        if rsa_enc["code"] == 200:
            show(
                "RSA解密",
                api_rsa_decrypt(rsa_enc["data"]["value"], private_key_pem=pri, input_encoding="base64", output="utf8"),
            )

        rsa_sig = show("RSA-SHA1签名", api_rsa_sign_sha1("hello", private_key_pem=pri, output="base64"))
        if rsa_sig["code"] == 200:
            show(
                "RSA-SHA1验签",
                api_rsa_verify_sha1(
                    "hello",
                    signature=rsa_sig["data"]["value"],
                    public_key_pem=pub,
                    signature_encoding="base64",
                ),
            )

    ecc_gen = show("ECC-160密钥生成", api_ecc_generate_keypair(trace=True))
    if ecc_gen["code"] == 200:
        ecc_pri = ecc_gen["data"]["private_key_pem"]
        ecc_pub = ecc_gen["data"]["public_key_pem"]

        ecdsa_sig = show("ECDSA-SHA1签名", api_ecdsa_sign_sha1("hello", private_key_pem=ecc_pri, output="base64"))
        if ecdsa_sig["code"] == 200:
            show(
                "ECDSA-SHA1验签",
                api_ecdsa_verify_sha1(
                    "hello",
                    signature=ecdsa_sig["data"]["value"],
                    public_key_pem=ecc_pub,
                    signature_encoding="base64",
                ),
            )
