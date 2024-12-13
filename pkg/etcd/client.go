package etcd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/k3s-io/k3s/pkg/daemons/config"
	k3setcd "github.com/k3s-io/k3s/pkg/etcd"
	"github.com/k3s-io/k3s/pkg/util"
	"github.com/k3s-io/k3s/pkg/version"
	certutil "github.com/rancher/dynamiclistener/cert"
	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/client/pkg/v3/logutil"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/credentials"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const (
	// defaultDialTimeout is intentionally short so that connections timeout within the testTimeout defined above
	defaultDialTimeout = 2 * time.Second
	// other defaults from k8s.io/apiserver/pkg/storage/storagebackend/factory/etcd3.go
	defaultKeepAliveTime    = 30 * time.Second
	defaultKeepAliveTimeout = 10 * time.Second
	heartbeatInterval       = 5 * time.Minute

	scheme = "etcd-endpoint"
)

// GetClient returns an etcd client connected to the specified endpoints.
// The returned client should be closed when no longer needed, in order to avoid leaking GRPC
// client goroutines.
func GetClient(ctx context.Context, control *config.Control, endpoints ...string) (*clientv3.Client, *grpc.ClientConn, error) {
	logger, err := logutil.CreateDefaultZapLogger(zapcore.DebugLevel)
	if err != nil {
		return nil, nil, err
	}

	cfg, err := getClientConfig(ctx, control, endpoints...)
	if err != nil {
		return nil, nil, err
	}

	// Set up dialer and resolver options.
	// This is normally handled by clientv3.New() but that wraps all the GRPC
	// service with retry handlers and uses deprecated grpc.DialContext() which
	// tries to establish a connection even when one isn't wanted.
	if cfg.DialKeepAliveTime > 0 {
		params := keepalive.ClientParameters{
			Time:                cfg.DialKeepAliveTime,
			Timeout:             cfg.DialKeepAliveTimeout,
			PermitWithoutStream: cfg.PermitWithoutStream,
		}
		cfg.DialOptions = append(cfg.DialOptions, grpc.WithKeepaliveParams(params))
	}

	if cfg.TLS != nil {
		creds := credentials.NewBundle(credentials.Config{TLSConfig: cfg.TLS}).TransportCredentials()
		cfg.DialOptions = append(cfg.DialOptions, grpc.WithTransportCredentials(creds))
	} else {
		cfg.DialOptions = append(cfg.DialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	cfg.DialOptions = append(cfg.DialOptions, grpc.WithResolvers(k3setcd.NewSimpleResolver(cfg.Endpoints[0])))

	target := fmt.Sprintf("%s://%p/%s", scheme, cfg, authority(cfg.Endpoints[0]))
	conn, err := grpc.NewClient(target, cfg.DialOptions...)
	if err != nil {
		return nil, nil, err
	}

	// Create a new client and wire up the GRPC service interfaces.
	// Ref: https://github.com/etcd-io/etcd/blob/v3.5.16/client/v3/client.go#L87
	client := clientv3.NewCtxClient(ctx, clientv3.WithZapLogger(logger.Named(version.Program+"-etcd-client")))
	client.Cluster = clientv3.NewClusterFromClusterClient(etcdserverpb.NewClusterClient(conn), client)
	client.KV = clientv3.NewKVFromKVClient(etcdserverpb.NewKVClient(conn), client)
	client.Maintenance = clientv3.NewMaintenanceFromMaintenanceClient(etcdserverpb.NewMaintenanceClient(conn), client)

	return client, conn, nil
}

func getClientConfig(ctx context.Context, control *config.Control, endpoints ...string) (*clientv3.Config, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no endpoints")
	}

	config := &clientv3.Config{
		Endpoints:            endpoints,
		Context:              ctx,
		DialTimeout:          defaultDialTimeout,
		DialKeepAliveTime:    defaultKeepAliveTime,
		DialKeepAliveTimeout: defaultKeepAliveTimeout,
		PermitWithoutStream:  true,
	}

	var err error
	if strings.HasPrefix(endpoints[0], "https://") {
		config.TLS, err = toTLSConfig(control.Runtime)
	}
	return config, err
}

func authority(ep string) string {
	if _, authority, ok := strings.Cut(ep, "://"); ok {
		return authority
	}
	if suff, ok := strings.CutPrefix(ep, "unix:"); ok {
		return suff
	}
	if suff, ok := strings.CutPrefix(ep, "unixs:"); ok {
		return suff
	}
	return ep
}

// toTLSConfig converts the ControlRuntime configuration to TLS configuration suitable
// for use by etcd.
func toTLSConfig(runtime *config.ControlRuntime) (*tls.Config, error) {
	if runtime.ClientETCDCert == "" || runtime.ClientETCDKey == "" || runtime.ETCDServerCA == "" {
		return nil, util.ErrCoreNotReady
	}

	clientCert, err := tls.LoadX509KeyPair(runtime.ClientETCDCert, runtime.ClientETCDKey)
	if err != nil {
		return nil, err
	}

	pool, err := certutil.NewPool(runtime.ETCDServerCA)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
	}, nil
}
