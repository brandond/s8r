package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/brandond/s8r/pkg/signals"
	"github.com/brandond/s8r/pkg/version"
	"github.com/k3s-io/k3s/pkg/authenticator"
	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/daemons/control/deps"
	"github.com/k3s-io/k3s/pkg/util"
	k3sversion "github.com/k3s-io/k3s/pkg/version"
	"github.com/pkg/errors"
	"github.com/rancher/dynamiclistener"
	"github.com/rancher/dynamiclistener/factory"
	filestorage "github.com/rancher/dynamiclistener/storage/file"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	k8sflag "k8s.io/component-base/cli/flag"
	utilsnet "k8s.io/utils/net"
)

var defaultCipherSuites = []string{
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
}

func init() {
	k3sversion.Program = version.Program
	k3sversion.ProgramUpper = version.ProgramUpper
	k3sversion.Version = version.GitVersion
	k3sversion.GitCommit = version.GitCommit
}

type Server struct {
	DataDir     string
	BindAddress string
	Port        int
	Debug       bool

	ctx    context.Context
	config *config.Control

	listener net.Listener
	dynamic  http.Handler
	router   http.Handler
}

func (s *Server) Run(_ *cli.Context) error {
	s.ctx = signals.SetupSignalContext()

	if err := s.setupControlConfig(); err != nil {
		return err
	}

	if err := s.newListener(); err != nil {
		return err
	}

	if err := s.newRouter(); err != nil {
		return err
	}

	server := http.Server{
		Handler: s,
	}

	// Start the supervisor http server on the tls listener
	go func() {
		logrus.Infof("Serving on %s", s.listener.Addr().String())
		if err := server.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Fatalf("server stopped: %v", err)
		}
	}()

	// Shutdown the http server when the context is closed
	<-s.ctx.Done()
	server.Shutdown(context.Background())

	return s.ctx.Err()
}

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
	s.config.DisableNPC = cfg.DisableNPC
	s.config.EgressSelectorMode = cfg.EgressSelectorMode
	s.config.EmbeddedRegistry = cfg.EmbeddedRegistry
	s.config.EncryptSecrets = cfg.EncryptSecrets
	s.config.SupervisorMetrics = cfg.SupervisorMetrics
	s.config.Token = cfg.Token

	// TODO: how to handle RBAC, CCM, and CNI across both products?
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

func (s *Server) newListener() error {
	tcp, err := util.ListenWithLoopback(s.ctx, s.BindAddress, strconv.Itoa(s.Port))
	if err != nil {
		return err
	}
	certs, key, err := factory.LoadCertsChain(s.config.Runtime.ServerCA, s.config.Runtime.ServerCAKey)
	if err != nil {
		return err
	}
	storage := filestorage.New(filepath.Join(s.config.DataDir, "tls", "dynamic-cert.json"))
	s.listener, s.dynamic, err = dynamiclistener.NewListenerWithChain(tcp, storage, certs, key, dynamiclistener.Config{
		Organization: []string{version.Program},
		SANs:         s.config.SANs,
		CN:           version.Program,
		TLSConfig: &tls.Config{
			ClientAuth:   tls.RequestClientCert,
			MinVersion:   s.config.TLSMinVersion,
			CipherSuites: s.config.TLSCipherSuites,
			NextProtos:   []string{"h2", "http/1.1"},
		},
	})
	return err
}
