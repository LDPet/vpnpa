package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteModeDoesNotWeaken(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "state", "vpnpa")
	path := filepath.Join(sub, "config.yaml")
	if err := Write(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", st.Mode().Perm())
	}
	st, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %o", st.Mode().Perm())
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("secret-2"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("weakened to %o", st.Mode().Perm())
	}
	if os.SameFile(before, st) {
		t.Fatal("rewritten in place")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret-2" {
		t.Fatalf("content %q", got)
	}
	old := make([]byte, 6)
	if _, err := f.ReadAt(old, 0); err != nil {
		t.Fatal(err)
	}
	if string(old) != "secret" {
		t.Fatalf("old inode changed: %q", old)
	}
	unit := filepath.Join(dir, "vpnpa.service")
	if err := Write(unit, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err = os.Stat(unit)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("unit mode %o", st.Mode().Perm())
	}
	entries, err := os.ReadDir(sub)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if stringsHasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp left behind: %s", e.Name())
		}
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
