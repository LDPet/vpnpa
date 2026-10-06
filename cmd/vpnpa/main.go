package main

import (
	"os"

	"github.com/LDPet/vpnpa/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
