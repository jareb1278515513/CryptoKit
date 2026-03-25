import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptokit.interfaces.api import api_hmac_text, api_pbkdf2


def show(name, result):
    payload = result.to_dict()
    print(f"[{name}] {json.dumps(payload, ensure_ascii=False)}")
    if payload["code"] != 200:
        print(f"[{name}] 第三方判断：调用失败，状态码={payload['code']}")


if __name__ == "__main__":
    show("HMAC-SHA1", api_hmac_text("hello", key="secret", algorithm="sha1", output="hex"))
    show("HMAC-SHA256", api_hmac_text("hello", key="secret", algorithm="sha256", output="hex"))

    show(
        "PBKDF2-SHA1",
        api_pbkdf2("password", "salt", iterations=1000, dklen=32, algorithm="sha1", output="hex", trace=True),
    )
    show(
        "PBKDF2-SHA256",
        api_pbkdf2("password", "salt", iterations=1000, dklen=32, algorithm="sha256", output="hex"),
    )
