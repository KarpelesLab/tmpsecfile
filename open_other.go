//go:build !linux

package tmpsecfile

import "os"

func openTmp() (*os.File, error) {
	return openTmpFallback()
}
