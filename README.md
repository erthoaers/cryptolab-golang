# cryptolab-golang

An educational Go library for implementing cryptographic algorithms from published standards. It includes source code, step-by-step guides, known-answer tests, and differential tests. There are no third-party dependencies. Go 1.27 or later is required.

## Algorithms

| Package | Scope | Status | Guide |
| --- | --- | --- | --- |
| `sha1` | SHA-1, with one-shot and streaming interfaces | Implemented for studying a historical algorithm | [SHA-1](docs/sha1.md) |
| `sha256` | SHA-224 and SHA-256, with one-shot and streaming interfaces | Implemented | [SHA-256](docs/sha256.md), [SHA-224](docs/sha224.md) |
| `sha512` | SHA-384, SHA-512, SHA-512/224, and SHA-512/256 | Implemented, including streaming input | [SHA-512 family](docs/sha512.md) |
| `aes` | AES-128, AES-192, and AES-256 | Implements `cipher.Block` | [AES](docs/aes.md) |
| `rsa` | PKCS #1 primitives, key validation and generation, MGF1, encryption, and signatures | OAEP, PSS, PKCS #1 v1.5, session-key fallback, key generation, and blinding helpers implemented; blinding integration into schemes pending | [RSA](docs/rsa.md) |
| `ed25519` | Pure Ed25519 from RFC 8032 | Step-by-step exercises; implementation pending | [Ed25519](docs/ed25519.md) |
| `sha3` | Four SHA-3 hashes (`hash.Hash`) and two SHAKE XOFs (`hash.XOF`) | Streaming interface scaffold; algorithms remain exercises | [FIPS 202](docs/fips202.md) |

SHA-224 and SHA-256 share the `sha256` package. The SHA-512 family shares the `sha512` package. SHA-3 and SHAKE share a Keccak core in the `sha3` package.

## Usage

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

The SHA packages provide one-shot digest functions and `New` constructors for streaming input. In `sha3`, `New224/256/384/512` return `hash.Hash`, and `NewSHAKE128/256` return `hash.XOF`. The one-shot functions reuse these streaming interfaces; the SHA-3/SHAKE algorithms remain TODO exercises. For AES, `NewCipher` creates a block cipher, and each `Encrypt` or `Decrypt` call processes 16 bytes. In-place operation is supported; short buffers or partial overlap between the first source and destination blocks cause a panic.

## Testing

Run these commands from the repository root:

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

The full test suite includes unfinished Ed25519 and SHA-3 / SHAKE exercises. Their tests currently fail at the remaining TODOs. The implemented RSA schemes, key generation, and blinding helpers have separate regression coverage. Compilation, test-vector transcription checks, and algorithm tests verify different properties. Tests for unfinished exercises are not skipped.

Each guide includes test commands for individual implementation steps. Implemented hash functions can also be fuzzed against the Go standard library:

```sh
go test ./sha256 -run '^$' -fuzz '^FuzzSum256AgainstStandard$' -fuzztime 10s
```

The PEM files in `rsa/testdata/` are public test keys for fixed fixtures and interoperability tests only. SHA-3 test data is stored in `sha3/testdata/`, with NIST source references and vector descriptions retained in the files.

## Standards

- [FIPS 180-4 (2015)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf): SHA-1 and SHA-2.
- [FIPS 197-upd1 (2023)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf): AES.
- [FIPS 202 (2015)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf): SHA-3 and SHAKE.
- [RFC 8017 (2016)](https://www.rfc-editor.org/rfc/rfc8017.html): PKCS #1 v2.2.
- [RFC 8032 (2017)](https://www.rfc-editor.org/rfc/rfc8032.html): EdDSA.
- [FIPS 186-5 (2023)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf): Digital signatures and RSA key generation.

Guides are in `docs/`; source code and tests are organized by algorithm package. Tests cite the relevant standard sections and data sources, and use the Go standard library as an independent reference. RSA's public interfaces reuse some standard-library types; cryptographic operations and encodings are implemented in this library.

This library is for learning. It has not undergone a security audit and must not be used to protect real secrets.
