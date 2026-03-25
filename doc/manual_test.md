# CryptoKit 阶段手动测试清单

本文档用于记录每个阶段完成后的手动测试命令、预期结果和验收标准。

## M1: 编码与哈希 + API/CLI 基线

### 1) 环境与测试基线
- 前置条件：已在项目根目录执行 uv sync。
- 命令：

```bash
uv run pytest -q
```

- 预期结果：全部通过（当前为 9 passed）。

### 2) CLI 手动测试
- SHA256:

```bash
uv run python main.py hash --text abc --algorithm sha256
```

- 预期结果：
  - code 为 200
  - data.value 为 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

- Base64 编码:

```bash
uv run python main.py base64-encode --text hello
```

- 预期结果：
  - code 为 200
  - data.value 为 aGVsbG8=

- Base64 解码:

```bash
uv run python main.py base64-decode --payload aGVsbG8=
```

- 预期结果：
  - code 为 200
  - data.value 为 hello

- 异常输入（非法 Base64）:

```bash
uv run python main.py base64-decode --payload "***"
```

- 预期结果：
  - 进程退出码为 1
  - 输出 JSON 的 code 为 501

### 3) API 手动测试
- 命令：

```bash
uv run python - <<'PY'
from cryptokit.interfaces.api import api_pbkdf2
r = api_pbkdf2("password", "salt", iterations=1, dklen=20, algorithm="sha1", output="hex")
print(r.to_dict())
PY
```

- 预期结果：
  - code 为 200
  - data.value 为 0c60c80f961f0e71f3a9b524af6012062fe037a6

### 4) M1 验收标准
- API 与 CLI 均可调用且返回统一 JSON 结构。
- 正常路径与异常路径均可复现。
- 单元测试可在 uv 环境中稳定通过。
