# CryptoKit 开发 TODO

> 目标：按课程要求完成密码算法实现、可调用接口、可测执行流程与报告交付。

> 过程约定：每个阶段完成后，必须同步更新手动测试步骤与预期结果，见 doc/manual_test.md。还要更新todo.md



## 0. 项目骨架与规范
- [x] 建立分层目录（interfaces/application/domain/infrastructure/shared）
- [x] 建立测试分层目录（unit/integration/e2e）
- [x] 创建共享基础文件（errors/result/types）
- [ ] 统一命名规范与导入规范（模块名、函数名、常量名）
- [ ] 定义跨层依赖约束检查规则（禁止反向依赖）

## 1. 工程依赖与运行基线
- [ ] 在 pyproject.toml 中补充运行依赖（cryptography、pycryptodome、gmssl）
- [x] 在 pyproject.toml 中补充开发依赖（pytest、ruff）
- [x] 配置并验证 `uv run` 运行入口
- [x] 配置并验证 `uv run pytest` 测试入口

## 2. 编码与哈希模块（优先）
- [x] 实现 Base64 编码/解码
- [x] 实现 UTF-8 编码/解码与异常处理
- [x] 实现 SHA1/SHA256/SHA3
- [x] 实现 HmacSHA1/HmacSHA256
- [x] 实现 PBKDF2
- [x] 实现 RIPEMD160（含可用性降级方案）
- [x] 编写对应单元测试（正常/异常/边界）

## 3. 对称加密模块
- [x] 实现 AES（ECB/CBC/CTR，含 IV 与 padding 约束）
- [x] 实现 SM4（基础加解密与模式参数）
- [x] 实现 RC6（纯 Python 手写，固定参数与说明）
- [x] 收集并接入标准测试向量（重点 RC6/SM4）
- [x] 编写对称加密单元测试

## 4. 公钥密码模块
- [ ] 实现 RSA-1024 密钥生成
- [ ] 实现 RSA-1024 加密/解密
- [ ] 实现 RSA-SHA1 签名/验签
- [ ] 实现 ECC-160（NIST P-160）密钥生成
- [ ] 实现 ECDSA 签名/验签
- [ ] 编写公钥算法单元测试

## 5. 应用层与接口层
- [x] 设计并实现统一 OperationResult 返回规范
- [ ] 建立 application/use_cases 编排流程（encrypt/decrypt/sign/verify/hash）
- [x] 暴露 Python API（interfaces/api）
- [x] 暴露 CLI 命令（interfaces/cli）
- [x] 保证 API 与 CLI 输出一致性

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
- [ ] 完成课程 PDF 报告提纲（对应评分五项，还要详细介绍每种算法原理，并且给出对应的运行截图）

## 8. 里程碑（建议）
- [x] M1：完成编码与哈希 + 单测通过
- [x] M2：完成对称加密 + 单测通过
- [ ] M3：完成公钥算法 + 单测通过
- [ ] M4：完成 API/CLI + integration/e2e 通过
- [ ] M5：完成文档与报告材料

## 9. 阶段手动测试同步
- [x] M1 手动测试步骤已记录到 doc/manual_test.md
- [x] M2 手动测试步骤已记录到 doc/manual_test.md
- [ ] M3 手动测试步骤已记录到 doc/manual_test.md
- [ ] M4 手动测试步骤已记录到 doc/manual_test.md
- [ ] M5 手动测试步骤已记录到 doc/manual_test.md
