package server

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/k3s-io/k3s/pkg/authenticator"
	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/daemons/control/deps"
	"github.com/k3s-io/k3s/pkg/util"
	"github.com/pkg/errors"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	k8sflag "k8s.io/component-base/cli/flag"
	utilsnet "k8s.io/utils/net"
)

// setupControlConfig sets up the server configuration struct based on the CLI flags,
// which is in turn used by the API request handlers to generate the configuration
// that is sent to joining nodes.  Much of this is cribbed from server.run():
// https://github.com/k3s-io/k3s/blob/v1.31.3%2Bk3s1/pkg/cli/server/server.go#L51
func (s *Server) setupControlConfig() error {
	cfg := &cmds.ServerConfig
	serverPaths := []string{
		filepath.Join(s.DataDir, "server", "etc"),
		filepath.Join(s.DataDir, "server", "cred"),
		filepath.Join(s.DataDir, "server", "tls"),
	}
	for _, path := range serverPaths {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
	}

	var err error
	s.config = &config.Control{
		Runtime: &config.ControlRuntime{},
		DataDir: filepath.Join(s.DataDir, "server"),
	}

	s.config.SupervisorPort = s.Port
	s.config.HTTPSPort = 6443
	s.config.APIServerPort = 6443

	s.config.AgentToken = cfg.AgentToken
	s.config.ClusterDomain = cfg.ClusterDomain
	s.config.DisableCCM = cfg.DisableCCM
	s.config.DisableHelmController = cfg.DisableHelmController
	s.config.DisableKubeProxy = cfg.DisableKubeProxy
	s.config.EgressSelectorMode = cfg.EgressSelectorMode
	s.config.EmbeddedRegistry = cfg.EmbeddedRegistry
	s.config.EncryptSecrets = cfg.EncryptSecrets
	s.config.SupervisorMetrics = cfg.SupervisorMetrics
	s.config.Token = cfg.Token

	// TODO: how to handle RBAC, CCM, and CNI across both products?
	s.config.DisableNPC = true
	s.config.DisableServiceLB = true
	s.config.FlannelBackend = "none"

	nodeName, nodeIPs, err := util.GetHostnameAndIPs(cmds.AgentConfig.NodeName, cmds.AgentConfig.NodeIP)
	if err != nil {
		return err
	}

	s.config.ServerNodeName = nodeName
	s.config.SANs = append(s.config.SANs, "127.0.0.1", "::1", "localhost", nodeName)
	for _, ip := range nodeIPs {
		s.config.SANs = append(s.config.SANs, ip.String())
	}

	_, defaultClusterCIDR, defaultServiceCIDR, _ := util.GetDefaultAddresses(nodeIPs[0])
	if len(cfg.ClusterCIDR) == 0 {
		cfg.ClusterCIDR.Set(defaultClusterCIDR)
	}
	for _, cidr := range util.SplitStringSlice(cfg.ClusterCIDR) {
		_, parsed, err := net.ParseCIDR(cidr)
		if err != nil {
			return errors.Wrapf(err, "invalid cluster-cidr %s", cidr)
		}
		s.config.ClusterIPRanges = append(s.config.ClusterIPRanges, parsed)
	}

	// set ClusterIPRange to the first address (first defined IPFamily is preferred)
	s.config.ClusterIPRange = s.config.ClusterIPRanges[0]

	// configure ServiceIPRanges. Use default 10.43.0.0/16 or fd00:43::/112 if user did not set it
	if len(cfg.ServiceCIDR) == 0 {
		cfg.ServiceCIDR.Set(defaultServiceCIDR)
	}
	for _, cidr := range util.SplitStringSlice(cfg.ServiceCIDR) {
		_, parsed, err := net.ParseCIDR(cidr)
		if err != nil {
			return errors.Wrapf(err, "invalid service-cidr %s", cidr)
		}
		s.config.ServiceIPRanges = append(s.config.ServiceIPRanges, parsed)
	}

	// set ServiceIPRange to the first address (first defined IPFamily is preferred)
	s.config.ServiceIPRange = s.config.ServiceIPRanges[0]

	s.config.ServiceNodePortRange, err = utilnet.ParsePortRange(cfg.ServiceNodePortRange)
	if err != nil {
		return errors.Wrapf(err, "invalid port range %s", cfg.ServiceNodePortRange)
	}

	// If cluster-dns CLI arg is not set, we set ClusterDNS address to be the first IPv4 ServiceCIDR network + 10,
	// i.e. when you set service-cidr to 192.168.0.0/16 and don't provide cluster-dns, it will be set to 192.168.0.10
	// If there are no IPv4 ServiceCIDRs, an IPv6 ServiceCIDRs will be used.
	// If neither of IPv4 or IPv6 are found an error is raised.
	if len(cfg.ClusterDNS) == 0 {
		for _, svcCIDR := range s.config.ServiceIPRanges {
			clusterDNS, err := utilsnet.GetIndexedIP(svcCIDR, 10)
			if err != nil {
				return errors.Wrap(err, "cannot configure default cluster-dns address")
			}
			s.config.ClusterDNSs = append(s.config.ClusterDNSs, clusterDNS)
		}
	} else {
		for _, ip := range util.SplitStringSlice(cfg.ClusterDNS) {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return fmt.Errorf("invalid cluster-dns address %s", ip)
			}
			s.config.ClusterDNSs = append(s.config.ClusterDNSs, parsed)
		}
	}

	s.config.ClusterDNS = s.config.ClusterDNSs[0]

	s.config.TLSMinVersion, err = k8sflag.TLSVersion("")
	if err != nil {
		return err
	}

	s.config.TLSCipherSuites, err = k8sflag.TLSCipherSuites(defaultCipherSuites)
	if err != nil {
		return err
	}

	deps.CreateRuntimeCertFiles(s.config)
	err = deps.GenServerDeps(s.config)
	if err != nil {
		return err
	}

	authArgs := []string{
		"--basic-auth-file=" + s.config.Runtime.PasswdFile,
		"--client-ca-file=" + s.config.Runtime.ClientCA,
	}
	s.config.Runtime.Authenticator, err = authenticator.FromArgs(authArgs)
	if err != nil {
		return err
	}

	s.config.Runtime.Tunnel, err = setupTunnel(s.ctx, s.config)
	return err
}
