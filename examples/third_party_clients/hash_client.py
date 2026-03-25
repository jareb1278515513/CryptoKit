import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptokit.interfaces.api import api_hash_text

ALGORITHMS = ["sha1", "sha256", "sha3_256", "sha3_512", "ripemd160"]


def show(name, result):
    payload = result.to_dict()
    print(f"[{name}] {json.dumps(payload, ensure_ascii=False)}")
    if payload["code"] != 200:
        print(f"[{name}] 第三方判断：调用失败，状态码={payload['code']}")


if __name__ == "__main__":
    for alg in ALGORITHMS:
        show(f"哈希-{alg}", api_hash_text("abc", algorithm=alg, output="hex", trace=True))
