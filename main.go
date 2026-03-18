package main

import (
	"fmt"
	"os"
)

func main() {
	ui := newUI()
	if err := ui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
