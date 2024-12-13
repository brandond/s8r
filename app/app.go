package app

import (
	"fmt"

	"github.com/brandond/s8r/pkg/server"
	"github.com/brandond/s8r/pkg/version"
	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/urfave/cli"
)

func init() {
	// Add a trailing newline after the help to separate it from error output
	cli.AppHelpTemplate = cli.AppHelpTemplate + "\n"
}

func New() *cli.App {
	s := server.Server{}
	ServerConfig := &cmds.ServerConfig
	return &cli.App{
		Name:     "s8r",
		Usage:    "Standalone supervisor API for K3s and RKE2",
		Action:   s.Run,
		Version:  fmt.Sprintf("%s (%.8s)", version.GitVersion, version.GitCommit),
		HideHelp: true,
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
			&cli.StringFlag{
				Name:        "egress-selector-mode",
				Usage:       "(networking) One of 'agent', 'cluster', 'pod', 'disabled'",
				Destination: &ServerConfig.EgressSelectorMode,
				Value:       "agent",
			},
			cmds.ServerToken,
			&cli.StringFlag{
				Name:        "agent-token",
				Usage:       "(cluster) Shared secret used to join agents to the cluster, but not servers",
				Destination: &ServerConfig.AgentToken,
				EnvVar:      version.ProgramUpper + "_AGENT_TOKEN",
			},
			cmds.ClusterCIDR,
			cmds.ServiceCIDR,
			cmds.ServiceNodePortRange,
			cmds.ClusterDNS,
			cmds.ClusterDomain,
			&cli.BoolFlag{
				Name:        "disable-helm-controller",
				Usage:       "(components) Disable Helm controller",
				Destination: &ServerConfig.DisableHelmController,
			},
			&cli.BoolFlag{
				Name:        "disable-controller-manager",
				Hidden:      true,
				Usage:       "(experimental/components) Disable running kube-controller-manager",
				Destination: &ServerConfig.DisableControllerManager,
			},
			&cli.BoolFlag{
				Name:        "embedded-registry",
				Usage:       "(components) Enable embedded distributed container registry; requires use of embedded containerd; when enabled agents will also listen on the supervisor port",
				Destination: &ServerConfig.EmbeddedRegistry,
			},
			&cli.BoolFlag{
				Name:        "supervisor-metrics",
				Usage:       "(experimental/components) Enable serving " + version.Program + " internal metrics on the supervisor port; when enabled agents will also listen on the supervisor port",
				Destination: &ServerConfig.SupervisorMetrics,
			},
			cmds.EnablePProfFlag,
			&cli.BoolFlag{
				Name:        "secrets-encryption",
				Usage:       "Enable secret encryption at rest",
				Destination: &ServerConfig.EncryptSecrets,
			},
		},
	}
}
