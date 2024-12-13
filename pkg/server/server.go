package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/brandond/s8r/pkg/signals"
	"github.com/brandond/s8r/pkg/version"
	"github.com/k3s-io/k3s/pkg/agent/loadbalancer"
	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/metrics"
	"github.com/k3s-io/k3s/pkg/profile"
	"github.com/k3s-io/k3s/pkg/util"
	k3sversion "github.com/k3s-io/k3s/pkg/version"
	"github.com/pkg/errors"
	"github.com/rancher/dynamiclistener"
	"github.com/rancher/dynamiclistener/factory"
	filestorage "github.com/rancher/dynamiclistener/storage/file"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
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

	apiserver *loadbalancer.LoadBalancer
	etcd      *loadbalancer.LoadBalancer
}

func (s *Server) Run(_ *cli.Context) error {
	s.ctx = signals.SetupSignalContext()

	if s.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if err := s.setupControlConfig(); err != nil {
		return err
	}

	if err := s.setupLoadBalancers(); err != nil {
		return err
	}

	if err := s.newListener(); err != nil {
		return err
	}

	if err := s.newRouter(); err != nil {
		return err
	}

	if cmds.ServerConfig.SupervisorMetrics {
		if err := metrics.DefaultMetrics.Start(s.ctx, nil); err != nil {
			return errors.Wrap(err, "failed to serve metrics")
		}
	}

	if cmds.AgentConfig.EnablePProf {
		if err := profile.DefaultProfiler.Start(s.ctx, nil); err != nil {
			return errors.Wrap(err, "failed to serve pprof")
		}
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
