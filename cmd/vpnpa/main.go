// Command vpnpa — локальный прокси. Команды, systemd и цикл демона
// живут в internal/cli; здесь только код возврата процесса.
package main

import (
	"os"

	"github.com/LDPet/vpnpa/internal/cli"
)

// main передаёт аргументы без имени программы в cli.Main.
// Код процесса: 0 — успех, 1 — ошибка команды, 2 — неверное использование.
func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
