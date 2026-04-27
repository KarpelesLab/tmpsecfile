// Package tmpsecfile provides a temporary file that is anonymous on disk
// (unlinked or O_TMPFILE) and transparently encrypted at rest with a
// per-file random AES-256-CTR key. The file supports random read/write
// and treats sparse holes (regions never written) as zeros.
package tmpsecfile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
)

const aesBlockSize = 16

// File is a secure anonymous temporary file. The on-disk representation
// is encrypted with AES-256-CTR using a key generated at New time and
// held only for the lifetime of this File. Logical length and the
// Read/Write cursor are tracked in this struct; the underlying *os.File
// is used purely as a backing store via ReadAt/WriteAt.
type File struct {
	f     *os.File
	block cipher.Block

	mu     sync.Mutex
	pos    int64
	length int64
}

// New creates a new anonymous encrypted temporary file.
func New() (*File, error) {
	osFile, err := openTmp()
	if err != nil {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		osFile.Close()
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		osFile.Close()
		return nil, err
	}

	return &File{f: osFile, block: block}, nil
}

func openTmpFallback() (*os.File, error) {
	f, err := os.CreateTemp("", "tmpsecfile-*")
	if err != nil {
		return nil, err
	}
	_ = os.Remove(f.Name())
	return f, nil
}

// fillKeystream writes the AES-CTR keystream covering [off, off+len(out))
// into out. off need not be aligned to the AES block size.
func (f *File) fillKeystream(out []byte, off int64) {
	if len(out) == 0 {
		return
	}
	blockIdx := uint64(off / aesBlockSize)
	blockOff := int(off % aesBlockSize)

	var counter [aesBlockSize]byte
	var ks [aesBlockSize]byte

	pos := 0
	for pos < len(out) {
		binary.BigEndian.PutUint64(counter[8:], blockIdx)
		f.block.Encrypt(ks[:], counter[:])

		n := copy(out[pos:], ks[blockOff:])
		pos += n
		blockOff = 0
		blockIdx++
	}
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// WriteAt encrypts p with the keystream at off and writes it to the
// backing file. Length is updated to reflect the highest written byte.
//
// Writes that touch only part of an AES block read-modify-write the
// whole block, so every block on disk is either fully encrypted (real
// ciphertext) or fully sparse (raw zeros). That invariant is what lets
// ReadAt distinguish written-zeros from never-written holes by inspecting
// the on-disk bytes alone.
func (f *File) WriteAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off < 0 {
		return 0, errors.New("tmpsecfile: negative offset")
	}

	end := off + int64(len(p))
	blkStart := off &^ int64(aesBlockSize-1)
	blkEnd := (end + int64(aesBlockSize-1)) &^ int64(aesBlockSize-1)
	bufLen := int(blkEnd - blkStart)
	headLen := int(off - blkStart)
	tailLen := int(blkEnd - end)

	plain := make([]byte, bufLen)
	if headLen > 0 || tailLen > 0 {
		// Pull in existing plaintext for the boundary bytes the user
		// isn't overwriting. Bytes past current length stay zero from make.
		if _, err := f.ReadAt(plain, blkStart); err != nil && err != io.EOF {
			return 0, err
		}
	}
	copy(plain[headLen:headLen+len(p)], p)

	enc := make([]byte, bufLen)
	f.fillKeystream(enc, blkStart)
	for i := range enc {
		enc[i] ^= plain[i]
	}

	n, err := f.f.WriteAt(enc, blkStart)
	if n >= bufLen {
		f.mu.Lock()
		if end > f.length {
			f.length = end
		}
		f.mu.Unlock()
		return len(p), err
	}
	// Partial disk write. Convert disk bytes written to user-visible bytes.
	written := int64(n) - int64(headLen)
	if written < 0 {
		return 0, err
	}
	if written > int64(len(p)) {
		written = int64(len(p))
	}
	if written > 0 {
		f.mu.Lock()
		if newEnd := off + written; newEnd > f.length {
			f.length = newEnd
		}
		f.mu.Unlock()
	}
	return int(written), err
}

// ReadAt reads up to len(p) bytes at off, decrypting on the fly. Regions
// of the backing file that read as all-zero AES blocks are treated as
// sparse holes and returned as zeros (no decryption attempted).
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off < 0 {
		return 0, errors.New("tmpsecfile: negative offset")
	}

	f.mu.Lock()
	length := f.length
	f.mu.Unlock()

	if off >= length {
		return 0, io.EOF
	}

	wantEnd := off + int64(len(p))
	if wantEnd > length {
		wantEnd = length
	}

	alignedStart := off &^ int64(aesBlockSize-1)
	alignedEnd := (wantEnd + int64(aesBlockSize-1)) &^ int64(aesBlockSize-1)
	buf := make([]byte, alignedEnd-alignedStart)

	if _, err := f.f.ReadAt(buf, alignedStart); err != nil && err != io.EOF {
		return 0, err
	}
	// If the backing file came up short, the tail of buf is the zeros that
	// make gave us, which the sparse-block check below treats as a hole.
	valid := int(wantEnd - alignedStart)

	fullBlocks := valid / aesBlockSize
	for i := 0; i < fullBlocks; i++ {
		bs := i * aesBlockSize
		blk := buf[bs : bs+aesBlockSize]
		if isZero(blk) {
			continue
		}
		var ks [aesBlockSize]byte
		f.fillKeystream(ks[:], alignedStart+int64(bs))
		for j := range blk {
			blk[j] ^= ks[j]
		}
	}
	if rem := valid % aesBlockSize; rem != 0 {
		bs := fullBlocks * aesBlockSize
		blk := buf[bs : bs+rem]
		if !isZero(blk) {
			ks := make([]byte, rem)
			f.fillKeystream(ks, alignedStart+int64(bs))
			for j := range blk {
				blk[j] ^= ks[j]
			}
		}
	}

	userStart := int(off - alignedStart)
	toCopy := int(wantEnd - off)
	copy(p, buf[userStart:userStart+toCopy])
	if toCopy < len(p) {
		return toCopy, io.EOF
	}
	return toCopy, nil
}

// Read reads from the current cursor position and advances it.
func (f *File) Read(p []byte) (int, error) {
	f.mu.Lock()
	pos := f.pos
	f.mu.Unlock()

	n, err := f.ReadAt(p, pos)

	if n > 0 {
		f.mu.Lock()
		f.pos = pos + int64(n)
		f.mu.Unlock()
	}
	return n, err
}

// Write writes at the current cursor position and advances it.
func (f *File) Write(p []byte) (int, error) {
	f.mu.Lock()
	pos := f.pos
	f.mu.Unlock()

	n, err := f.WriteAt(p, pos)

	if n > 0 {
		f.mu.Lock()
		f.pos = pos + int64(n)
		f.mu.Unlock()
	}
	return n, err
}

// Seek moves the Read/Write cursor.
func (f *File) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var p int64
	switch whence {
	case io.SeekStart:
		p = offset
	case io.SeekCurrent:
		p = f.pos + offset
	case io.SeekEnd:
		p = f.length + offset
	default:
		return 0, errors.New("tmpsecfile: invalid whence")
	}
	if p < 0 {
		return 0, errors.New("tmpsecfile: negative position")
	}
	f.pos = p
	return p, nil
}

// Truncate sets the logical (and on-disk) length of the file. Extending
// creates a sparse hole; subsequent reads from the new region return zeros.
func (f *File) Truncate(size int64) error {
	if size < 0 {
		return errors.New("tmpsecfile: negative size")
	}
	if err := f.f.Truncate(size); err != nil {
		return err
	}
	f.mu.Lock()
	f.length = size
	f.mu.Unlock()
	return nil
}

// Size returns the current logical length of the file.
func (f *File) Size() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.length
}

// Close releases the backing file. The encryption key is dropped along
// with the File value (no method to retrieve it exists).
func (f *File) Close() error {
	return f.f.Close()
}
