# SHA-1

[sha1/sha1.go](../sha1/sha1.go) 实现 FIPS 180-4（2015）的 SHA-1，提供一次性入口 `Sum(data []byte) [20]byte` 和满足 `hash.Hash` 接口的 `New()`。只接受完整字节消息，`nil` 与空切片等价。SHA-1 保留用于历史学习，不用于新的安全设计。

## 算法结构

SHA-1 以 64 字节为块，使用五个 32 位状态字，输出 20 字节摘要。填充在消息末尾追加 `0x80`、若干零和 8 字节大端比特长度；原消息尾部超过 55 字节时，需要两个填充块。

消息扩展先把块按大端序解析为 16 个字，再扩展到 80 个字：

```text
W[t] = ROTL1(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16])
```

80 轮分为四组，每组 20 轮，分别使用 `Ch`、奇偶、`Maj`、奇偶函数及对应常量。每轮计算：

```text
T = ROTL5(a) + f(t, b, c, d) + e + K[t] + W[t]
(a, b, c, d, e) = (T, a, ROTL30(b), c, d)
```

所有加法按模 `2^32` 进行。80 轮结束后，把五个工作变量加回输入状态；下一块从这个累加后的状态开始。每次创建或重置摘要对象都复制固定 IV，不能修改全局初始值。

## 阅读与测试顺序

以下命令在仓库根目录执行。对应测试见 [sha1/sha1_test.go](../sha1/sha1_test.go)。

| 步骤 | 标准章节 | 验证命令 |
| --- | --- | --- |
| 核对固定向量 | NIST SHA1 示例 | `go test ./sha1 -run '^TestVectorFixtures$' -count=1 -v` |
| 消息扩展 `schedule` | §§5.2.1、6.1.2 第 1 步 | `go test ./sha1 -run '^TestSchedule$' -count=1 -v` |
| 压缩 `compress` | §§4.1.1、4.2.1、6.1.2 第 2–4 步 | `go test ./sha1 -run '^TestCompress$' -count=1 -v` |
| 一次性摘要与填充 | §§5.1.1、5.3.1、6.1.2 | `go test ./sha1 -run '^TestSum' -count=1 -v` |
| 分块写入与长度限制 | §5.1.1、`hash.Hash` 契约 | `go test ./sha1 -run '^TestStreaming' -count=1 -v` |
| 完整测试 | 上述算法与接口行为 | `go test ./sha1 -count=1` |

填充由 `checkSum` 完成，没有独立的 `pad` 函数。`Write` 处理完整块并保存剩余字节；`Sum` 复制状态后填充，将摘要追加到传入切片，允许随后继续 `Write`。`Reset` 恢复 IV、计数器与缓冲区长度。

`schedule` 和 `compress` 测试使用固定的已填充 `abc` 块，可独立于填充逻辑定位问题。扩展字检查点按标准推导，压缩预期包含最终状态累加。接口测试还覆盖 55/56、63/64 字节边界、多块输入、实例隔离、输入不变性及 `io.Reader` 集成。

标准规定消息少于 `2^64` 比特，完整字节输入因此最多为 `2^61 - 1` 字节。长度上限测试构造内部计数器状态，检查拒绝越界写入及 `Sum` 的状态保护；它不代表实际计算过接近该上限的消息。

```sh
# Compile without running tests.
go test ./sha1 -run '^$'

# Fuzz streaming writes against the standard library.
go test ./sha1 -run '^$' -fuzz '^FuzzStreamingAgainstStandard$' -fuzztime 10s
```

`TestVectorFixtures` 只核对向量录入；编译和向量核对不能替代算法测试。`crypto/sha1` 仅用于测试中的独立对照。标准 §6.1.3 的 16 字循环缓冲实现可作为后续比较练习。

## 来源

- [FIPS 180-4（2015）](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)：§§4.1.1、4.2.1、5.1.1、5.2.1、5.3.1、6.1。
- [NIST SHA1.pdf](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf)：`abc` 和 56 字节消息的官方示例，后者填充后占两个块。
