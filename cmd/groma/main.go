package main

import (
	"fmt"
	"os"

	"github.com/TyrusRC/groma/cmd/groma/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(cmd.ExitCode(err))
	}
}
