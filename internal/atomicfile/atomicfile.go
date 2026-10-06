// Package atomicfile writes a file by creating a temporary sibling and renaming
// it into place. Readers never observe a partial file, and an existing file
// does not gain group or world permission bits.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write creates path with mode using a temp file in the same directory.
// mode is the permission of a new file. When path already exists, group and
// world bits that are not already set are cleared so a rewrite cannot weaken
// a 0600 config or state file.
func Write(path string, data []byte, mode os.FileMode) error {
	if path == "" || path == "." {
		return fmt.Errorf("atomicfile: empty path")
	}
	mode = mode.Perm()
	if mode == 0 {
		mode = 0o600
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if st, err := os.Lstat(path); err == nil && st.Mode().IsRegular() {
		mode = restrictPerm(st.Mode().Perm(), mode)
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil { // #nosec G302 -- mode is 0600 for secrets; an existing file cannot gain group or world bits
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// restrictPerm keeps owner bits from requested and drops group/world bits
// that the existing file does not already have.
func restrictPerm(existing, requested os.FileMode) os.FileMode {
	const groupWorld = os.FileMode(0o077)
	return (requested &^ groupWorld) | (requested & existing & groupWorld)
}
