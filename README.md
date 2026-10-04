# cryptolab-golang

按密码学标准实现算法的 Go 学习库，包含源码、分步导读、已知答案和差分测试。无第三方依赖，需要 Go 1.27 或更高版本。

## 算法

| 包 | 范围 | 实现情况 | 导读 |
| --- | --- | --- | --- |
| `sha1` | SHA-1，一次性与流式接口 | 已实现，用于历史算法学习 | [SHA-1](docs/sha1.md) |
| `sha256` | SHA-224、SHA-256，一次性与流式接口 | 已实现 | [SHA-256](docs/sha256.md)、[SHA-224](docs/sha224.md) |
| `sha512` | SHA-384、SHA-512、SHA-512/224、SHA-512/256 | 已实现，支持流式输入 | [SHA-512 家族](docs/sha512.md) |
| `aes` | AES-128、AES-192、AES-256 | 已实现 `cipher.Block` | [AES](docs/aes.md) |
| `rsa` | PKCS #1 原语、密钥检查、MGF1、加解密与签名 | 原语和哈希接线已实现；密钥生成及完整方案待完成 | [RSA](docs/rsa.md) |
| `ed25519` | RFC 8032 的普通 Ed25519 | 分步练习，尚待实现 | [Ed25519](docs/ed25519.md) |
| `sha3` | 四种 SHA-3、SHAKE128、SHAKE256 | 分步练习，尚待实现 | [FIPS 202](docs/fips202.md) |

SHA-224 与 SHA-256 共用 `sha256` 包；SHA-512 家族共用 `sha512` 包；SHA-3 和 SHAKE 的 Keccak 核心集中在 `sha3` 包。

## 使用

```go
package main

import (
    "fmt"

    "github.com/erthoaers/cryptolab-golang/sha256"
)

func main() {
    sum := sha256.Sum256([]byte("abc"))
    fmt.Printf("%x\n", sum)
}
```

SHA 包提供一次性摘要和 `New` 系列流式构造函数。AES 通过 `NewCipher` 创建分组密码，每次 `Encrypt` / `Decrypt` 处理 16 字节；支持原地操作，短缓冲区或首块部分重叠会 panic。

## 测试

在仓库根目录运行：

```sh
# Build all packages and tests without executing them.
go test ./... -run '^$'

# Run the implemented SHA and AES packages.
go test ./sha1 ./sha256 ./sha512 ./aes -count=1

# Check fixture transcription independently of the algorithms.
go test ./... -run '^Test.*VectorFixtures$' -count=1

# Run every test, including unfinished exercises.
go test ./... -count=1

go vet ./...
```

完整测试包含尚未实现的 RSA 方案、Ed25519 和 SHA-3 / SHAKE，相关测试目前会因 TODO 失败。编译、向量录入核对和算法测试分别验证不同内容；未完成测试不跳过。

各篇导读提供针对单个步骤的测试命令。已实现的哈希函数还可与标准库进行持续模糊测试：

```sh
go test ./sha256 -run '^$' -fuzz '^FuzzSum256AgainstStandard$' -fuzztime 10s
```

`rsa/testdata/` 中的 PEM 文件是公开测试密钥，仅供固定案例与互操作测试使用。SHA-3 测试数据保存在 `sha3/testdata/`，文件内保留 NIST 来源与向量说明。

## 标准

- [FIPS 180-4（2015）](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)：SHA-1 和 SHA-2。
- [FIPS 197-upd1（2023）](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)：AES。
- [FIPS 202（2015）](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)：SHA-3 和 SHAKE。
- [RFC 8017（2016）](https://www.rfc-editor.org/rfc/rfc8017.html)：PKCS #1 v2.2。
- [RFC 8032（2017）](https://www.rfc-editor.org/rfc/rfc8032.html)：EdDSA。
- [FIPS 186-5（2023）](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)：数字签名及 RSA 密钥生成。

导读位于 `docs/`；源码和测试按算法包组织。测试注明标准章节和数据出处，并以 Go 标准库作独立比较。RSA 的公开接口复用部分标准库类型，密码运算和编码在本库实现。

本库用于学习，未经安全审计，不用于保护真实秘密。
