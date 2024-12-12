package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/brandond/s8r/app"
)

func main() {
	if err := app.New().Run(os.Args); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
