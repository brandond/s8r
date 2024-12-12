package app

import (
	"fmt"

	"github.com/brandond/s8r/pkg/server"
	"github.com/brandond/s8r/pkg/version"
	"github.com/urfave/cli/v2"
)

func init() {
	// Add a trailing newline after the help to separate it from error output
	cli.AppHelpTemplate = cli.AppHelpTemplate + "\n"
}

func New() *cli.App {
	s := server.Server{}
	return &cli.App{
		Name:            "s8r",
		Usage:           "Standalone supervisor API for K3s and RKE2",
		Action:          s.Run,
		Version:         fmt.Sprintf("%s (%.8s)", version.GitVersion, version.GitCommit),
		HideHelpCommand: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "data-dir",
				Destination: &s.DataDir,
				Usage:       "Folder to hold state.",
				Value:       "/var/lib/rancher/s8r",
			},
			&cli.StringFlag{
				Name:        "bind-address",
				Destination: &s.BindAddress,
				Usage:       "The IP address on which to listen for the --port port. If blank or an unspecified address (0.0.0.0 or ::), all interfaces and IP address families will be used.",
			},
			&cli.IntFlag{
				Name:        "port",
				Destination: &s.Port,
				Usage:       "The port on which to serve HTTPS.",
				Value:       9345,
			},
			&cli.BoolFlag{
				Name:        "debug",
				Destination: &s.Debug,
				Usage:       "Enable debug logging",
			},
		},
	}
}
