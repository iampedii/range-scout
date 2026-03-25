package main

import (
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	log.SetOutput(io.Discard)

	ui := newUI()
	if err := ui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
