import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptokit.interfaces.api import api_symmetric_decrypt, api_symmetric_encrypt

AES_KEY = "00112233445566778899aabbccddeeff"
AES_IV = "000102030405060708090a0b0c0d0e0f"
SM4_KEY = "0123456789abcdeffedcba9876543210"
RC6_KEY = "000102030405060708090a0b0c0d0e0f"


def show(name, result):
    payload = result.to_dict()
    print(f"[{name}] {json.dumps(payload, ensure_ascii=False)}")
    return payload


if __name__ == "__main__":
    aes_enc = api_symmetric_encrypt(
        "hello",
        algorithm="aes",
        mode="cbc",
        key_hex=AES_KEY,
        iv_hex=AES_IV,
        output="hex",
        trace=True,
    )
    aes_enc_payload = show("AES-CBC加密", aes_enc)

    if aes_enc_payload["code"] == 200:
        aes_dec = api_symmetric_decrypt(
            aes_enc_payload["data"]["value"],
            algorithm="aes",
            mode="cbc",
            key_hex=AES_KEY,
            iv_hex=AES_IV,
            input_encoding="hex",
            output="utf8",
        )
        show("AES-CBC解密", aes_dec)

    show(
        "SM4-ECB加密",
        api_symmetric_encrypt(
            "0123456789abcdeffedcba9876543210",
            algorithm="sm4",
            mode="ecb",
            key_hex=SM4_KEY,
            input_encoding="hex",
            output="hex",
        ),
    )

    show(
        "RC6-ECB加密",
        api_symmetric_encrypt(
            "000102030405060708090a0b0c0d0e0f",
            algorithm="rc6",
            mode="ecb",
            key_hex=RC6_KEY,
            input_encoding="hex",
            output="hex",
        ),
    )

    # 错误路径演示：第三方程序根据状态码做分支处理。
    bad_key = api_symmetric_encrypt(
        "hello",
        algorithm="aes",
        mode="cbc",
        key_hex="0011",
        iv_hex=AES_IV,
        output="hex",
    )
    bad_payload = show("AES非法密钥", bad_key)
    if bad_payload["code"] != 200:
        print(f"[AES非法密钥] 第三方判断：拒绝请求，状态码={bad_payload['code']}")
