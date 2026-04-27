# tmpsecfile

[![test](https://github.com/KarpelesLab/tmpsecfile/actions/workflows/test.yml/badge.svg)](https://github.com/KarpelesLab/tmpsecfile/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/KarpelesLab/tmpsecfile/badge.svg?branch=master)](https://coveralls.io/github/KarpelesLab/tmpsecfile?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/KarpelesLab/tmpsecfile)](https://goreportcard.com/report/github.com/KarpelesLab/tmpsecfile)
[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/tmpsecfile.svg)](https://pkg.go.dev/github.com/KarpelesLab/tmpsecfile)

A Go package that gives you a temporary file which is:

- **Anonymous on disk.** On Linux it's opened with `O_TMPFILE`, so the inode has no name in any directory. On other systems it falls back to `os.CreateTemp` immediately followed by `os.Remove` — best-effort, but the same observable result on Unix-like filesystems.
- **Encrypted at rest.** Every write is AES-256-CTR encrypted with a fresh per-file random key. The key lives only inside the `*File` value; there is no API to retrieve it.
- **Random-access friendly.** `Read`, `Write`, `ReadAt`, `WriteAt`, `Seek`, and `Truncate` work the way they do on `*os.File`.
- **Sparse-aware.** A region you never wrote (because you `Truncate`-extended past it, or `WriteAt`-ed at a higher offset and skipped some bytes) reads back as zeros — without keeping any allocation map.

Designed for staging untrusted or sensitive data on disk during a single process's lifetime: large uploads, intermediate caches, swap-out buffers — anything where the bytes shouldn't survive a crash, an `lsof`, or someone reading the device.

## Install

```sh
go get github.com/KarpelesLab/tmpsecfile
```

Stdlib only, no dependencies. Requires Go 1.25+.

## Usage

```go
package main

import (
    "fmt"
    "io"

    "github.com/KarpelesLab/tmpsecfile"
)

func main() {
    f, err := tmpsecfile.New()
    if err != nil {
        panic(err)
    }
    defer f.Close()

    // Random-access write at any offset.
    if _, err := f.WriteAt([]byte("hello"), 13); err != nil {
        panic(err)
    }

    // Reads of unwritten regions return zeros, not garbage or an error.
    buf := make([]byte, 32)
    n, err := f.ReadAt(buf, 0)
    fmt.Printf("read %d bytes (err=%v): %q\n", n, err, buf[:n])
    // read 18 bytes (err=EOF): "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00hello"

    // The visible length is byte-exact.
    fmt.Println("size:", f.Size()) // 18

    // Stream-style use also works.
    f.Seek(0, io.SeekStart)
    f.Write([]byte("overwrite"))
}
```

## API

```go
func New() (*File, error)

func (*File) Read(p []byte) (int, error)
func (*File) Write(p []byte) (int, error)
func (*File) ReadAt(p []byte, off int64) (int, error)
func (*File) WriteAt(p []byte, off int64) (int, error)
func (*File) Seek(offset int64, whence int) (int64, error)
func (*File) Truncate(size int64) error
func (*File) Size() int64
func (*File) Close() error
```

`Read` / `Write` use an internal cursor like `*os.File`. `ReadAt` / `WriteAt` are independent of the cursor and safe to call concurrently with each other.

## How it works

- **Cipher.** AES-256-CTR. The 32-byte key is generated from `crypto/rand` at `New` time. The CTR counter for any byte at offset `o` is `o / 16`, big-endian. Because the key is unique per file, there is no nonce — `(key, counter)` pairs are unique by construction.

- **Sparse detection.** When `ReadAt` reads back the underlying file, every 16-byte AES block is checked: if every byte is zero, the block is treated as a sparse hole and returned as zeros. Otherwise it's decrypted normally. Writing plaintext zeros encrypts to a non-zero ciphertext block, so reads of *written* zero data round-trip correctly; only never-written holes hit the sparse path.

- **The block-alignment invariant.** For sparse detection to work, every AES block on disk must be either *fully* sparse (raw zeros) or *fully* encrypted — never a mix. `WriteAt` enforces this by reading-modifying-writing the boundary blocks of any unaligned write.

- **Logical length.** The struct keeps its own `length` separate from `os.File.Stat().Size()`. Unaligned writes near the end leave `Size()` byte-exact (e.g., 5 bytes at offset 13 → `Size() == 18`, not 32) even though the on-disk file has been extended to the next AES block boundary.

## Caveats

- **Whole-block false positive.** A real ciphertext block whose 16 bytes happen to all be zero will be treated as a sparse hole. Probability per block: 2⁻¹²⁸. The check always inspects the full 16 bytes on disk, so this rate holds even for sub-block files (a 1-byte file is still backed by a full 16-byte block on disk and gets the full 128 bits of evidence).
- **Process-lifetime only.** When the `*File` is closed (or the process exits) the data is unrecoverable. There is no API to persist the key.
- **Memory hygiene.** The package does not zero key material on `Close`. Go's GC may keep the cipher state around after the `*File` is unreachable. If you need defense against in-process memory disclosure, wrap with `mlock` / `memguard` yourself.
- **Anonymity on non-Linux.** macOS, BSD, and Linux without `O_TMPFILE` support get the `CreateTemp + Remove` fallback. The file is unlinked immediately, so it's gone from the directory listing, but on Windows the file may remain visible until close.

## License

MIT — see [LICENSE](LICENSE).
