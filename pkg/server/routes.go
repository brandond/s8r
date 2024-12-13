package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/brandond/s8r/pkg/auth/nodepassword"
	"github.com/brandond/s8r/pkg/etcd"
	"github.com/brandond/s8r/pkg/handlers"
	"github.com/brandond/s8r/pkg/version"
	"github.com/gorilla/mux"
	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/metrics"
	"github.com/k3s-io/k3s/pkg/profile"
	"github.com/k3s-io/k3s/pkg/server/auth"
	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"k8s.io/apiserver/pkg/authentication/user"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
)

func (s *Server) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		req.Header.Add("User-Agent", "mozilla")
	}
	s.dynamic.ServeHTTP(resp, req)
	s.config.Runtime.Handler.ServeHTTP(resp, req)
}

func (s *Server) newRouter() error {
	prefix := "/{apiroot:v1-(?:k3s|rke2)}"
	nodeAuth := nodepassword.GetNodeAuthValidator(s.ctx, s.config)
	apiGetter, etcdGetter, err := s.infoGetters()
	if err != nil {
		return err
	}

	authed := mux.NewRouter().SkipClean(true)
	authed.NotFoundHandler = handlers.NotFound()
	authed.Use(auth.HasRole(s.config, version.Program+":agent", user.NodesGroup, bootstrapapi.BootstrapDefaultGroup))
	authed.Handle(prefix+"/serving-kubelet.crt", handlers.ServingKubeletCert(s.config, s.config.Runtime.ServingKubeletKey, nodeAuth))
	authed.Handle(prefix+"/client-kubelet.crt", handlers.ClientKubeletCert(s.config, s.config.Runtime.ClientKubeletKey, nodeAuth))
	authed.Handle(prefix+"/client-kube-proxy.crt", handlers.File(s.config.Runtime.ClientKubeProxyCert, s.config.Runtime.ClientKubeProxyKey))
	authed.Handle(prefix+"/client-{product:(?:k3s|rke2)}-controller.crt", handlers.File(s.config.Runtime.ClientK3sControllerCert, s.config.Runtime.ClientK3sControllerKey))
	authed.Handle(prefix+"/client-ca.crt", handlers.File(s.config.Runtime.ClientCA))
	authed.Handle(prefix+"/server-ca.crt", handlers.File(s.config.Runtime.ServerCA))
	authed.Handle(prefix+"/apiservers", handlers.APIServers(s.config, apiGetter))
	authed.Handle(prefix+"/config", handlers.Config(s.config, nil))
	authed.Handle(prefix+"/readyz", handlers.Readyz(s.config))

	nodeAuthed := mux.NewRouter().SkipClean(true)
	nodeAuthed.NotFoundHandler = authed
	nodeAuthed.Use(auth.HasRole(s.config, user.NodesGroup))
	nodeAuthed.Handle(prefix+"/connect", s.config.Runtime.Tunnel)

	serverAuthed := mux.NewRouter().SkipClean(true)
	serverAuthed.NotFoundHandler = nodeAuthed
	serverAuthed.Use(auth.HasRole(s.config, version.Program+":server"))
	serverAuthed.Handle(prefix+"/server-bootstrap", handlers.Bootstrap(s.config))
	serverAuthed.Handle("/db/info", handlers.DBInfo(s.config, etcdGetter))

	router := mux.NewRouter().SkipClean(true)
	router.NotFoundHandler = serverAuthed
	router.Handle("/cacerts", handlers.CACerts(s.config))
	router.Handle("/ping", handlers.Ping())

	// wire up metrics and pprof
	metrics.DefaultMetrics.Router = func(ctx context.Context, nodeConfig *config.Node) (*mux.Router, error) { return router, nil }
	profile.DefaultProfiler.Router = func(ctx context.Context, nodeConfig *config.Node) (*mux.Router, error) { return router, nil }

	s.config.Runtime.Handler = router

	return nil
}

// return helper functions to retrieve apiserver and etcd member addresses from etcd
func (s *Server) infoGetters() (handlers.APIServerAddressGetter, handlers.ETCDMemberGetter, error) {
	client, conn, err := etcd.GetClient(s.ctx, s.config, s.etcd.LocalURL())
	if err != nil {
		return nil, nil, err
	}
	go func() {
		<-s.ctx.Done()
		conn.Close()
	}()

	apiGetter := func(ctx context.Context) []string {
		// each product stashes its addresses at a different key, so we need to try all of them and merge the results
		// TODO: watch or poll the product keys and cross-populate between them?
		var addresses []string
		for _, product := range version.Products {
			etcdResp, err := client.KV.Get(ctx, product+"/apiaddresses")
			if err != nil {
				continue
			}

			if etcdResp.Count == 0 || len(etcdResp.Kvs[0].Value) == 0 {
				continue
			}

			var pAddrs []string
			if err := json.Unmarshal(etcdResp.Kvs[0].Value, &pAddrs); err != nil {
				continue
			}
			addresses = append(addresses, pAddrs...)
		}

		return addresses
	}

	etcdGetter := func(ctx context.Context, remoteAddr string) []*etcdserverpb.Member {
		if res, err := client.Cluster.MemberList(ctx); err == nil {
			// Try to use endpoints from the etcd cluster via our loadbalancer
			return res.Members
		}

		// If that fails, return a single endpoint generated from the joining node's address,
		// and set it as the loadbalancer default address, assuming it will be starting a new cluster.
		host, _, _ := net.SplitHostPort(remoteAddr)
		s.etcd.SetDefault(net.JoinHostPort(host, "2379"))
		return []*etcdserverpb.Member{{
			ClientURLs: []string{"https://" + net.JoinHostPort(host, "2379")},
			PeerURLs:   []string{"https://" + net.JoinHostPort(host, "2380")},
		}}
	}

	return apiGetter, etcdGetter, nil
}
