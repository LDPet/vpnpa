//go:build !windows

package paths

import "os"

// Default строит Linux-раскладку от домашнего каталога текущего пользователя.
func Default() (Layout, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Layout{}, err
	}
	return FromHome(home), nil
}
