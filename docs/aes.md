# AES：从字节运算到 cipher.Block

`aes` 包实现 AES-128、AES-192、AES-256 的单块加解密，包括字节变换、密钥扩展和 `cipher.Block` 接口。本文按实现步骤说明标准中的数据布局、轮流程和接口约定；`crypto/aes` 仅用于测试对照。

统一入口为 `NewCipher(key []byte) (cipher.Block, error)`，支持 16、24、32 字节密钥，分别对应 AES-128、AES-192、AES-256。创建对象后调用 `Encrypt` 或 `Decrypt`；三种密钥长度的分组都为 16 字节，单块接口不包含填充、文件加密或工作模式。

文件按职责组织：[aes.go](../aes/aes.go) 包含接口、方法及全部算法辅助函数，[const.go](../aes/const.go) 保存 S-box 数据，[aes_test.go](../aes/aes_test.go) 集中保存全部验收测试。接口使用与轮流程见下方 [cipher.Block](#cipher-block)。

## 先读标准

- [NIST FIPS 197 发布页](https://csrc.nist.gov/pubs/fips/197/final)：版本信息与配套资料。
- [FIPS 197-upd1（2023）](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)：§3.4 状态布局，§4 有限域，§5.1 加密，§5.2 密钥扩展，§5.3 解密。
- [NIST AES_Core128 逐步示例](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf)：提供四组输入输出和中间状态。测试将其作为四个独立的单块向量使用。

注意版本：2023 版附录 A.1 保留了 AES-128 密钥扩展示例；附录 C 只指向外部向量，不能把旧版附录 C.1 的内容当作新版章节。

## 状态布局

Go 用 `[16]byte` 保存标准中的 4×4 矩阵，采用 `state[r+4*c]`，其中 `r` 是行、`c` 是列。字节索引在矩阵中如下：

```text
 0   4   8  12
 1   5   9  13
 2   6  10  14
 3   7  11  15
```

先在纸上画一次输入如何进入状态、状态如何输出为字节串。行移动时尤其容易把布局读反。

## 分步回顾与验收

从 `cryptolab-golang` 目录运行下列命令，可分别定位每个变换和完整轮流程。

| 步骤 | 实现内容 | 标准位置 | 验收命令 |
| --- | --- | --- | --- |
| AES-01 | `xtime`，理解字节表示的多项式及约简 | §4，尤其 §4.2 | `go test ./aes -run '^TestXtime$' -v` |
| AES-02 | `subBytes`，自行录入标准 S-box，或按标准定义生成 | §5.1.1、表 4 | `go test ./aes -run '^TestSubBytes$' -v` |
| AES-03 | `shiftRows`，留意原地修改时读写覆盖 | §5.1.2 | `go test ./aes -run '^TestShiftRows$' -v` |
| AES-04 | `mixColumns`、`addRoundKey` | §§5.1.3–5.1.4 | `go test ./aes -run '^Test(MixColumns\|AddRoundKey)$' -v` |
| AES-05 | `expandKey`，支持 44 / 52 / 60 个字，分别为 176 / 208 / 240 字节；此项逐轮测试覆盖 AES-128 | §5.2、附录 A.1–A.3 | `go test ./aes -run '^TestExpandKey$' -v` |
| AES-06 | `Encrypt`，根据标准组织各轮 | §5.1 | `go test ./aes -run '^TestEncryptKnownAnswers$' -v` |
| AES-07 | 三个 `inv` 变换，逆 S-box 见表 6 | §§5.3.1–5.3.3 | `go test ./aes -run '^TestInverseTransforms$' -v` |
| AES-08 | `Decrypt` | §5.3 | `go test ./aes -run '^TestDecryptKnownAnswers$' -v` |

逆变换的章节顺序与正向变换不同：`invShiftRows` 见 §5.3.1，`invSubBytes` 见 §5.3.2，`invMixColumns` 见 §5.3.3。正向 S-box 在表 4，逆 S-box 在表 6。

表格中的 AES-04 正则如果复制后仍带有 Markdown 的转义符，请使用：

```sh
go test ./aes -run '^Test(MixColumns|AddRoundKey)$' -v
```

S-box 是标准给定的数据表；可以对照 `const.go` 回顾查表与录入，再回到 §4.4 和 §5.1.1 理解生成原理。先保证字节顺序和每个变换正确，再考虑优化。

<a id="cipher-block"></a>

## 实现 cipher.Block

[aes.go](../aes/aes.go) 使用标准库定义的 `cipher.Block` 接口类型，算法在本包实现。

```go
type Block interface {
    BlockSize() int
    Encrypt(dst, src []byte)
    Decrypt(dst, src []byte)
}
```

`aesCipher` 保存 `expanded []byte` 与 `rounds int`，`var _ cipher.Block = (*aesCipher)(nil)` 检查方法签名。包内常量 `blockSize` 为 16，调用者通过 `BlockSize()` 获取分组长度。

| 步骤 | 实现要点 | 验收命令 |
| --- | --- | --- |
| AES-B01 | `NewCipher` 调用现有 `expandKey`，错误时返回 `nil, err`，成功时把扩展密钥和轮数保存在新对象内 | `go test ./aes -run '^TestBlockConstructor$' -v` |
| AES-B02 | `Encrypt` 检查缓冲区，复制首块为局部状态，再按 §5.1 组织各轮并写回首块 | `go test ./aes -run '^TestBlockKnownAnswers$/AES.*/Encrypt$' -v` |
| AES-B03 | `Decrypt` 使用同一扩展密钥倒序执行 §5.3 的逆变换 | `go test ./aes -run '^TestBlockKnownAnswers$/AES.*/Decrypt$' -v` |
| AES-B04 | 检查三种密钥长度、原地操作、边界、别名及重复调用 | `go test ./aes -run '^TestBlock' -v` |

创建对象时只扩展一次密钥。之后每次调用把 `src[:16]` 复制为局部 `[16]byte` 状态，运算完成后写入 `dst[:16]`；不要把每次调用的状态保存为对象字段，也不要修改对象中的轮密钥。这样一个对象就可以反复处理不同分组，且不受调用者后续修改原密钥切片的影响。

取第 `r` 组轮密钥时，使用 `[16]byte(c.expanded[16*r : 16*(r+1)])`；轮号分别是 `0..10`、`0..12`、`0..14`。

```text
Encrypt:
    AddRoundKey(K0)
    r = 1 .. Nr-1: SubBytes → ShiftRows → MixColumns → AddRoundKey(Kr)
    SubBytes → ShiftRows → AddRoundKey(KNr)

Decrypt:
    AddRoundKey(KNr)
    r = Nr-1 .. 1: InvShiftRows → InvSubBytes → AddRoundKey(Kr) → InvMixColumns
    InvShiftRows → InvSubBytes → AddRoundKey(K0)
```

### 缓冲区约定

[cipher.Block 文档](https://pkg.go.dev/crypto/cipher#Block) 规定每次只处理首个分组，并允许完全重叠或不重叠的输入输出。本包按 Go 1.27.1 标准库 AES 的方式检查缓冲区：

- `len(src)` 和 `len(dst)` 都至少为 16；不足时 `panic`。判断长度，不是容量。
- 只读取 `src[:16]`、写入 `dst[:16]`；更长切片可以传入，目标尾部保持不变。
- 两个首块从同一地址开始时允许原地操作，例如 `b.Encrypt(buf, buf)`。
- 两个首块完全不重叠时允许，包括同一个底层数组中的两个独立区间。
- 首块部分重叠时 `panic`，例如 `b.Encrypt(buf[1:17], buf[:16])`。先检查长度，再检查重叠，最后才能写输出。

这些 `panic` 检查是对齐标准库 AES 的行为；`cipher.Block` 接口注释本身没有逐项规定错误类型和文字。项目测试不要求错误文字与标准库完全相同。无需从标准库导入不可访问的 `internal/alias`；固定 16 字节范围可以通过比较元素地址判断交叠。完全同起点需先放行。

重叠只比较实际处理的两个首块。例如 `b.Encrypt(buf[16:32], buf[:32])` 合法：输入首块和输出首块相邻，但输入切片的尾部会作为输出改变。

### 测试来源与范围

算法以 FIPS 197-upd1（2023）§§5.1–5.3 为准，接口行为以 Go 1.27.1 的 `cipher.Block` 和 `crypto/aes` 为对照。三条固定输入输出分别取自 NIST 的 [AES_Core128](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf)、[AES_Core192](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core192.pdf)、[AES_Core256](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core256.pdf) 的第一个分组；独立调用分组原语，不实现这些示例标题中的多块 ECB 接口。

`TestBlockVectorFixtures` 只核对固定数据。其余 `TestBlock*` 验收三种密钥长度的加解密及接口行为，包括短缓冲区、部分重叠、原地操作、密钥独立性与重复调用。`TestEncryptKnownAnswers` 和 `TestDecryptKnownAnswers` 通过同一 `NewCipher` 接口核对四条 AES-128 向量。还需运行整个 AES 包，覆盖辅助函数、中间状态和密钥扩展。

## 如何解释测试结果

先检查练习中的已知答案是否录入正确：

```sh
go test ./aes -run '^Test(Block)?VectorFixtures$' -v
```

这些测试只核对固定向量与 Go 标准库，不能代替算法测试。中间状态测试定位错误步骤；密钥扩展测试逐轮核对 AES-128 的全部 11 个轮密钥；加密、解密测试分别核对官方固定答案。

完成后运行：

```sh
go test ./aes -v
```

`TestDifferential` 使用零值、全 `ff` 和固定种子生成的 64 组输入，分别对照标准库的加密和解密结果。`TestRoundTrip` 只作补充：一对彼此抵消的错误函数也可能往返成功，因此不能凭它判定符合标准。

这里不承诺常数时间或侧信道抵抗；即使功能测试全部通过，仍是学习实现。
