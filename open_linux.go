//go:build linux

package tmpsecfile

import (
	"os"
	"syscall"
)

// O_TMPFILE is defined in the Linux UAPI as (020000000 | O_DIRECTORY) and has
// the same value across every Linux architecture. The Go stdlib exposes it
// only on a subset of arches (arm64, s390x, riscv64, etc.), so we pin the
// constant locally to keep amd64 and friends working without pulling in
// golang.org/x/sys.
const o_TMPFILE = 0x410000

func openTmp() (*os.File, error) {
	fd, err := syscall.Open(os.TempDir(), o_TMPFILE|syscall.O_RDWR|syscall.O_CLOEXEC, 0o600)
	if err == nil {
		return os.NewFile(uintptr(fd), ""), nil
	}
	return openTmpFallback()
}
