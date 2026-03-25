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

- RIPEMD160:

```bash
uv run python main.py hash --text abc --algorithm ripemd160
```

- 预期结果：
  - code 为 200
  - data.value 为 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc

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

## M2: 对称加密模块（AES/SM4/RC6）

### 1) 单元测试
- 命令：

```bash
uv run pytest -q tests/unit/test_symmetric.py
```

- 预期结果：全部通过。

### 2) CLI 手动测试
- AES-CBC 加密（UTF-8 输入，Hex 输出）：

```bash
uv run python main.py symmetric-encrypt \
  --algorithm aes \
  --mode cbc \
  --payload hello \
  --key-hex 00112233445566778899aabbccddeeff \
  --iv-hex 000102030405060708090a0b0c0d0e0f \
  --output hex
```

- 预期结果：
  - code 为 200
  - data.value 为非空十六进制密文

- AES-CBC 解密（使用上一步密文）：

```bash
uv run python main.py symmetric-decrypt \
  --algorithm aes \
  --mode cbc \
  --payload <上一步密文hex> \
  --key-hex 00112233445566778899aabbccddeeff \
  --iv-hex 000102030405060708090a0b0c0d0e0f \
  --input-encoding hex \
  --output utf8
```

- 预期结果：
  - code 为 200
  - data.value 为 hello

- SM4-ECB 向量验证（首块）：

```bash
uv run python main.py symmetric-encrypt \
  --algorithm sm4 \
  --mode ecb \
  --payload 0123456789abcdeffedcba9876543210 \
  --input-encoding hex \
  --key-hex 0123456789abcdeffedcba9876543210 \
  --output hex
```

- 预期结果：
  - code 为 200
  - data.value 前 32 个十六进制字符为 681edf34d206965e86b3e94f536e4246

- RC6-ECB 向量验证（首块）：

```bash
uv run python main.py symmetric-encrypt \
  --algorithm rc6 \
  --mode ecb \
  --payload 000102030405060708090a0b0c0d0e0f \
  --input-encoding hex \
  --key-hex 000102030405060708090a0b0c0d0e0f \
  --output hex
```

- 预期结果：
  - code 为 200
  - data.value 前 32 个十六进制字符为 3a96f9c7f6755cfe46f00e3dcd5d2a3c

### 3) M2 验收标准
- AES/SM4/RC6 均支持 encrypt/decrypt。
- 至少覆盖 ECB/CBC/CTR 的可调用性（CTR 需传入 16 字节 iv）。
- CLI 与 API 返回结构一致，异常输入返回 code 500。

## M3: 公钥密码模块（RSA-1024 + ECC-160/ECDSA）

### 1) 单元测试
- 命令：

```bash
uv run pytest -q tests/unit/test_asymmetric.py
```

- 预期结果：全部通过。

### 2) CLI 手动测试
- 生成 RSA-1024 密钥对：

```bash
uv run python main.py rsa-generate
```

- 预期结果：
  - code 为 200
  - data.private_key_pem 和 data.public_key_pem 为非空 PEM 文本

- RSA-SHA1 签名/验签（文件方式，便于粘贴）

```bash
# 先将 rsa-generate 输出中的私钥与公钥分别保存为 /tmp/rsa_pri.pem /tmp/rsa_pub.pem
uv run python main.py rsa-sign --payload hello --private-key-file /tmp/rsa_pri.pem
```

- 预期结果：
  - code 为 200
  - data.value 为非空签名（base64）

```bash
# 将上一步签名替换到 <sig>
uv run python main.py rsa-verify --payload hello --signature <sig> --public-key-file /tmp/rsa_pub.pem
```

- 预期结果：
  - code 为 200
  - data.verified 为 true

- 生成 ECC-160 密钥对：

```bash
uv run python main.py ecc-generate
```

- 预期结果：
  - code 为 200
  - data.curve 为 nist-p160
  - data.private_key_pem 与 data.public_key_pem 为非空

- ECDSA-SHA1 签名/验签（文件方式）：

```bash
# 先将 ecc-generate 输出中的私钥与公钥分别保存为 /tmp/ecc_pri.pem /tmp/ecc_pub.pem
uv run python main.py ecdsa-sign --payload hello --private-key-file /tmp/ecc_pri.pem
```

- 预期结果：
  - code 为 200
  - data.value 为非空签名（base64）

```bash
# 将上一步签名替换到 <sig>
uv run python main.py ecdsa-verify --payload hello --signature <sig> --public-key-file /tmp/ecc_pub.pem
```

- 预期结果：
  - code 为 200
  - data.verified 为 true

### 3) M3 验收标准
- RSA-1024：密钥生成、加解密、RSA-SHA1 签名验签全部可用。
- ECC-160（SECP160r1，对应 NIST P-160）：密钥生成、ECDSA-SHA1 签名验签可用。
- API 与 CLI 均可调用，返回统一结构。

## M4: 应用层与接口层（use_cases + integration/e2e）

### 1) 自动化测试
- 命令：

```bash
uv run pytest -q tests/integration tests/e2e
```

- 预期结果：全部通过。

### 2) 手动一致性验证（API 与 CLI）
- 命令（CLI）：

```bash
uv run python main.py hash --text abc --algorithm sha256 --output hex
```

- 命令（API）：

```bash
uv run python -c "from cryptokit.interfaces.api import api_hash_text; print(api_hash_text('abc', algorithm='sha256', output='hex').to_dict())"
```

- 预期结果：
  - 两次输出的 data.value 相同。

### 3) 端到端验证（RSA CLI 流程）
- 命令：

```bash
uv run python main.py rsa-generate
```

- 预期结果：
  - 返回 code=200，包含 public_key_pem/private_key_pem。

```bash
# 将私钥、公钥分别保存为 /tmp/rsa_pri.pem /tmp/rsa_pub.pem
uv run python main.py rsa-sign --payload hello --private-key-file /tmp/rsa_pri.pem
```

```bash
# 将签名替换到 <sig>
uv run python main.py rsa-verify --payload hello --signature <sig> --public-key-file /tmp/rsa_pub.pem
```

- 预期结果：
  - 验签返回 code=200，data.verified=true。

### 4) M4 验收标准
- interfaces 层不直接编排 domain，统一经 application/use_cases 调用。
- integration 与 e2e 测试通过。
- API 与 CLI 关键路径输出一致。

## 错误码覆盖验证（输入错误 / 密钥错误 / 模式错误）

### 1) 自动化验证
- 命令：

```bash
uv run pytest -q tests/integration/test_error_codes.py
```

- 预期结果：全部通过。

### 2) 手动验证命令
- 输入错误（hex 非法输入）：

```bash
uv run python main.py symmetric-encrypt \
  --algorithm aes \
  --mode cbc \
  --payload zz \
  --input-encoding hex \
  --key-hex 00112233445566778899aabbccddeeff \
  --iv-hex 000102030405060708090a0b0c0d0e0f \
  --output hex
```

- 预期结果：返回 code=400。

- 密钥错误（密钥长度非法）：

```bash
uv run python main.py symmetric-encrypt \
  --algorithm aes \
  --mode cbc \
  --payload hello \
  --key-hex 0011 \
  --iv-hex 000102030405060708090a0b0c0d0e0f \
  --output hex
```

- 预期结果：返回 code=401。

- 模式错误（通过 API 验证不支持模式）：

```bash
uv run python -c "from cryptokit.interfaces.api import api_symmetric_encrypt; print(api_symmetric_encrypt('hello', algorithm='aes', mode='gcm', key_hex='00112233445566778899aabbccddeeff', iv_hex='000102030405060708090a0b0c0d0e0f', output='hex').to_dict())"
```

- 预期结果：返回 code=402。

## 可见中间过程模式（Trace）验证

### 1) 自动化验证
- 命令：

```bash
uv run pytest -q tests/e2e/test_trace_mode.py
```

- 预期结果：通过。

### 2) CLI 手动验证
- 哈希过程可视化：

```bash
uv run python main.py --trace hash --text hello --algorithm sha256
```

- 预期结果：
  - code 为 200
  - data.trace 存在且为步骤列表
  - trace 内容包含算法名 sha256

- 对称加密过程可视化：

```bash
uv run python main.py --trace symmetric-encrypt \
  --algorithm aes \
  --mode cbc \
  --payload hello \
  --key-hex 00112233445566778899aabbccddeeff \
  --iv-hex 000102030405060708090a0b0c0d0e0f \
  --output hex
```

- 预期结果：
  - code 为 200
  - data.trace 存在，包含输入解码、算法模式、密钥长度校验、加密执行、输出编码等步骤
