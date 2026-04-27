package tmpsecfile

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"runtime"
	"testing"
)

func newTest(t *testing.T) *File {
	t.Helper()
	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestRoundTrip(t *testing.T) {
	f := newTest(t)
	data := []byte("hello, secure tempfile world")
	if n, err := f.WriteAt(data, 0); err != nil || n != len(data) {
		t.Fatalf("WriteAt: n=%d err=%v", n, err)
	}
	if got := f.Size(); got != int64(len(data)) {
		t.Fatalf("Size: got %d want %d", got, len(data))
	}
	got := make([]byte, len(data))
	if n, err := f.ReadAt(got, 0); err != nil || n != len(data) {
		t.Fatalf("ReadAt: n=%d err=%v", n, err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch:\n got %q\nwant %q", got, data)
	}
}

func TestRandomReadWrite(t *testing.T) {
	f := newTest(t)
	type chunk struct {
		off  int64
		data []byte
	}
	chunks := []chunk{
		{0, bytes.Repeat([]byte("A"), 17)},
		{100, bytes.Repeat([]byte("B"), 33)},
		{1000, bytes.Repeat([]byte("C"), 7)},
		{10000, bytes.Repeat([]byte("D"), 64)},
	}
	for _, c := range chunks {
		if _, err := f.WriteAt(c.data, c.off); err != nil {
			t.Fatalf("WriteAt off=%d: %v", c.off, err)
		}
	}
	wantLen := chunks[len(chunks)-1].off + int64(len(chunks[len(chunks)-1].data))
	if got := f.Size(); got != wantLen {
		t.Fatalf("Size: got %d want %d", got, wantLen)
	}
	for _, c := range chunks {
		got := make([]byte, len(c.data))
		if _, err := f.ReadAt(got, c.off); err != nil {
			t.Fatalf("ReadAt off=%d: %v", c.off, err)
		}
		if !bytes.Equal(got, c.data) {
			t.Fatalf("chunk@%d mismatch:\n got %q\nwant %q", c.off, got, c.data)
		}
	}
}

func TestUnalignedNearEndKeepsExactLength(t *testing.T) {
	f := newTest(t)
	if _, err := f.WriteAt([]byte("hello"), 13); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if got := f.Size(); got != 18 {
		t.Fatalf("Size: got %d want 18 (must not round to AES block boundary)", got)
	}
}

func TestSparseHoleAfterTruncate(t *testing.T) {
	f := newTest(t)
	const size = int64(1 << 20) // 1 MiB
	if err := f.Truncate(size); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if got := f.Size(); got != size {
		t.Fatalf("Size: got %d want %d", got, size)
	}
	got := make([]byte, 4096)
	if _, err := f.ReadAt(got, 1000); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	for i, b := range got {
		if b != 0 {
			t.Fatalf("sparse region byte %d = %d, want 0", i, b)
		}
	}

	if _, err := f.WriteAt([]byte("start"), 0); err != nil {
		t.Fatalf("WriteAt 0: %v", err)
	}
	if _, err := f.WriteAt([]byte("middle"), 100_000); err != nil {
		t.Fatalf("WriteAt 100000: %v", err)
	}

	mid := make([]byte, 256)
	if _, err := f.ReadAt(mid, 50_000); err != nil {
		t.Fatalf("ReadAt mid: %v", err)
	}
	for i, b := range mid {
		if b != 0 {
			t.Fatalf("middle sparse byte %d = %d, want 0", i, b)
		}
	}

	check := make([]byte, 5)
	if _, err := f.ReadAt(check, 0); err != nil {
		t.Fatalf("ReadAt 0: %v", err)
	}
	if !bytes.Equal(check, []byte("start")) {
		t.Fatalf("offset 0: got %q want \"start\"", check)
	}
	check2 := make([]byte, 6)
	if _, err := f.ReadAt(check2, 100_000); err != nil {
		t.Fatalf("ReadAt 100000: %v", err)
	}
	if !bytes.Equal(check2, []byte("middle")) {
		t.Fatalf("offset 100000: got %q want \"middle\"", check2)
	}
}

func TestUnalignedReadAcrossSparseAndDense(t *testing.T) {
	f := newTest(t)
	if _, err := f.WriteAt([]byte("hello"), 13); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	got := make([]byte, 32)
	n, err := f.ReadAt(got, 0)
	if err != io.EOF {
		t.Fatalf("ReadAt err: got %v want EOF", err)
	}
	if n != 18 {
		t.Fatalf("ReadAt n: got %d want 18", n)
	}
	for i := 0; i < 13; i++ {
		if got[i] != 0 {
			t.Fatalf("byte %d in sparse prefix = %d, want 0", i, got[i])
		}
	}
	if !bytes.Equal(got[13:18], []byte("hello")) {
		t.Fatalf("data region: got %q want \"hello\"", got[13:18])
	}
	for i := 18; i < 32; i++ {
		if got[i] != 0 {
			t.Fatalf("byte %d past EOF should be unmodified zero, got %d", i, got[i])
		}
	}
}

func TestReadWriteCursor(t *testing.T) {
	f := newTest(t)
	msg := []byte("cursor-tracked write")
	if n, err := f.Write(msg); err != nil || n != len(msg) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	if pos, err := f.Seek(0, io.SeekCurrent); err != nil || pos != int64(len(msg)) {
		t.Fatalf("SeekCurrent after Write: pos=%d err=%v", pos, err)
	}
	if pos, err := f.Seek(0, io.SeekStart); err != nil || pos != 0 {
		t.Fatalf("SeekStart: pos=%d err=%v", pos, err)
	}
	got := make([]byte, len(msg))
	if n, err := f.Read(got); err != nil || n != len(msg) {
		t.Fatalf("Read: n=%d err=%v", n, err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("cursor read mismatch:\n got %q\nwant %q", got, msg)
	}
	if pos, err := f.Seek(0, io.SeekEnd); err != nil || pos != int64(len(msg)) {
		t.Fatalf("SeekEnd: pos=%d err=%v", pos, err)
	}
	if _, err := f.Seek(-1, io.SeekStart); err == nil {
		t.Fatal("Seek to negative should error")
	}
}

func TestEOFSemantics(t *testing.T) {
	f := newTest(t)
	if _, err := f.WriteAt([]byte("abc"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	got := make([]byte, 5)
	n, err := f.ReadAt(got, 0)
	if err != io.EOF || n != 3 {
		t.Fatalf("partial ReadAt: n=%d err=%v want 3 EOF", n, err)
	}
	if !bytes.Equal(got[:3], []byte("abc")) {
		t.Fatalf("partial data: got %q want \"abc\"", got[:3])
	}
	n, err = f.ReadAt(got, 100)
	if err != io.EOF || n != 0 {
		t.Fatalf("past-EOF ReadAt: n=%d err=%v want 0 EOF", n, err)
	}
}

func TestEncryptionAtRest(t *testing.T) {
	f := newTest(t)
	plain := make([]byte, 4096)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(plain, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	raw := make([]byte, 4096)
	if _, err := f.f.ReadAt(raw, 0); err != nil {
		t.Fatalf("raw ReadAt: %v", err)
	}
	if bytes.Equal(raw, plain) {
		t.Fatal("raw on-disk bytes equal plaintext — encryption is not active")
	}
	// Sanity: decrypted via our API should match.
	got := make([]byte, len(plain))
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypt roundtrip failed")
	}
}

func TestUniqueKeyPerFile(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	plain := []byte("identical plaintext")
	if _, err := a.WriteAt(plain, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := b.WriteAt(plain, 0); err != nil {
		t.Fatal(err)
	}
	rawA := make([]byte, len(plain))
	rawB := make([]byte, len(plain))
	if _, err := a.f.ReadAt(rawA, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := b.f.ReadAt(rawB, 0); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rawA, rawB) {
		t.Fatal("two separate files produced identical ciphertext for the same plaintext — keys are not unique")
	}
}

func TestTruncateShrinks(t *testing.T) {
	f := newTest(t)
	if _, err := f.WriteAt(bytes.Repeat([]byte("X"), 100), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := f.Truncate(10); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if got := f.Size(); got != 10 {
		t.Fatalf("Size after shrink: got %d want 10", got)
	}
	got := make([]byte, 100)
	n, err := f.ReadAt(got, 0)
	if !errors.Is(err, io.EOF) || n != 10 {
		t.Fatalf("ReadAt after shrink: n=%d err=%v want 10 EOF", n, err)
	}
	if !bytes.Equal(got[:10], bytes.Repeat([]byte("X"), 10)) {
		t.Fatalf("data after shrink: got %q", got[:10])
	}
}

func TestAnonymousOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("O_TMPFILE only on Linux")
	}
	f := newTest(t)
	if name := f.f.Name(); name != "" {
		t.Fatalf("expected empty name from O_TMPFILE, got %q (fallback was used)", name)
	}
}
