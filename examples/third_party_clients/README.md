# 第三方调用示例

本目录提供第三方程序调用 CryptoKit Python API 的示例脚本。

## 文件说明

- `encoding_client.py`：UTF-8、Base64
- `hash_client.py`：SHA1、SHA256、SHA3-256、SHA3-512、RIPEMD160
- `hmac_kdf_client.py`：HMAC-SHA1、HMAC-SHA256、PBKDF2
- `symmetric_client.py`：AES、SM4、RC6
- `asymmetric_client.py`：RSA-1024、RSA-SHA1、ECC-160、ECDSA-SHA1

## 运行方式

在项目根目录执行：

```bash
uv run python examples/third_party_clients/encoding_client.py
uv run python examples/third_party_clients/hash_client.py
uv run python examples/third_party_clients/hmac_kdf_client.py
uv run python examples/third_party_clients/symmetric_client.py
uv run python examples/third_party_clients/asymmetric_client.py
```

## 展示能力

每个脚本都展示以下能力：

- 第三方程序调用 API
- 返回统一结构化结果（`code`、`message`、`data`）
- 第三方程序基于状态码进行业务分支判断
