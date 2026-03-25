import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptokit.interfaces.api import (
    api_base64_decode,
    api_base64_encode,
    api_utf8_decode,
    api_utf8_encode,
)


def show(name, result):
    payload = result.to_dict()
    print(f"[{name}] {json.dumps(payload, ensure_ascii=False)}")
    if payload["code"] == 200:
        print(f"[{name}] 第三方判断：调用成功")
    else:
        print(f"[{name}] 第三方判断：调用失败，状态码={payload['code']}")


if __name__ == "__main__":
    show("UTF-8编码", api_utf8_encode("hello", output="hex", trace=True))
    show("UTF-8解码", api_utf8_decode("68656c6c6f", encoding="hex"))
    show("Base64编码", api_base64_encode("hello"))
    show("Base64解码", api_base64_decode("aGVsbG8="))
