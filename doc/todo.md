# CryptoKit 开发 TODO

> 目标：按课程要求完成密码算法实现、可调用接口、可测执行流程与报告交付。

## 0. 项目骨架与规范
- [x] 建立分层目录（interfaces/application/domain/infrastructure/shared）
- [x] 建立测试分层目录（unit/integration/e2e）
- [x] 创建共享基础文件（errors/result/types）
- [ ] 统一命名规范与导入规范（模块名、函数名、常量名）
- [ ] 定义跨层依赖约束检查规则（禁止反向依赖）

## 1. 工程依赖与运行基线
- [ ] 在 pyproject.toml 中补充运行依赖（cryptography、pycryptodome、gmssl）
- [ ] 在 pyproject.toml 中补充开发依赖（pytest、ruff）
- [ ] 配置并验证 `uv run` 运行入口
- [ ] 配置并验证 `uv run pytest` 测试入口

## 2. 编码与哈希模块（优先）
- [ ] 实现 Base64 编码/解码
- [ ] 实现 UTF-8 编码/解码与异常处理
- [ ] 实现 SHA1/SHA256/SHA3
- [ ] 实现 HmacSHA1/HmacSHA256
- [ ] 实现 PBKDF2
- [ ] 实现 RIPEMD160（含可用性降级方案）
- [ ] 编写对应单元测试（正常/异常/边界）

## 3. 对称加密模块
- [ ] 实现 AES（ECB/CBC/CTR，含 IV 与 padding 约束）
- [ ] 实现 SM4（基础加解密与模式参数）
- [ ] 实现 RC6（纯 Python 手写，固定参数与说明）
- [ ] 收集并接入标准测试向量（重点 RC6/SM4）
- [ ] 编写对称加密单元测试

## 4. 公钥密码模块
- [ ] 实现 RSA-1024 密钥生成
- [ ] 实现 RSA-1024 加密/解密
- [ ] 实现 RSA-SHA1 签名/验签
- [ ] 实现 ECC-160（NIST P-160）密钥生成
- [ ] 实现 ECDSA 签名/验签
- [ ] 编写公钥算法单元测试

## 5. 应用层与接口层
- [ ] 设计并实现统一 OperationResult 返回规范
- [ ] 建立 application/use_cases 编排流程（encrypt/decrypt/sign/verify/hash）
- [ ] 暴露 Python API（interfaces/api）
- [ ] 暴露 CLI 命令（interfaces/cli）
- [ ] 保证 API 与 CLI 输出一致性

## 6. 端到端验证
- [ ] 编写 integration 测试（跨层流程）
- [ ] 编写 e2e 测试（CLI/API 调用）
- [ ] 校验错误码覆盖（输入错误、密钥错误、模式错误）
- [ ] 形成可复现实验命令清单

## 7. 文档与报告交付
- [x] 完成项目设计计划文档
- [ ] README 补充快速开始与命令示例
- [ ] README 补充模块分层说明与依赖关系图
- [ ] 生成执行结果截图与说明（算法输入/输出/状态码）
- [ ] 整理接口调用示例（第三方调用 API + CLI）
- [ ] 完成课程 PDF 报告提纲（对应评分五项）

## 8. 里程碑（建议）
- [ ] M1：完成编码与哈希 + 单测通过
- [ ] M2：完成对称加密 + 单测通过
- [ ] M3：完成公钥算法 + 单测通过
- [ ] M4：完成 API/CLI + integration/e2e 通过
- [ ] M5：完成文档与报告材料
