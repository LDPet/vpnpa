// Package atomicfile записывает файл через временного соседа и rename.
// Читатель не видит обрезанный файл: rename в одном каталоге атомарен.
// Так пишутся конфиг, status.json, prefer и unit. Обновление бинарника
// в internal/cli использует тот же приём отдельно.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write создаёт path с правами mode. Данные сначала попадают во временный
// файл в том же каталоге, сбрасываются на диск и только потом переименовываются
// поверх path. Если path уже есть, групповые и «мировые» биты, которых у него
// не было, снимаются: перезапись не может ослабить конфиг или state с правами 0600.
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
	if err := f.Chmod(mode); err != nil { // #nosec G302 -- для секретов mode 0600; у существующего файла group/world не прибавляются
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Rename в том же каталоге подменяет inode атомарно. Каталог тоже
	// синхронизируется, иначе после сбоя запись может не доехать до диска.
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

// restrictPerm оставляет биты владельца из requested и сохраняет group/world
// только там, где они уже были у existing.
func restrictPerm(existing, requested os.FileMode) os.FileMode {
	const groupWorld = os.FileMode(0o077)
	return (requested &^ groupWorld) | (requested & existing & groupWorld)
}
