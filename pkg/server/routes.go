package server

import (
	"net/http"

	"github.com/brandond/s8r/pkg/auth/nodepassword"
	"github.com/brandond/s8r/pkg/handlers"
	"github.com/brandond/s8r/pkg/version"
	"github.com/gorilla/mux"
	"github.com/k3s-io/k3s/pkg/server/auth"
	"k8s.io/apiserver/pkg/authentication/user"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
)

func (s *Server) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		req.Header.Add("User-Agent", "mozilla")
	}
	s.dynamic.ServeHTTP(resp, req)
	s.router.ServeHTTP(resp, req)
}

func (s *Server) newRouter() error {
	prefix := "/{apiroot:v1-(?:k3s|rke2)}"
	nodeAuth := nodepassword.GetNodeAuthValidator(s.ctx, s.config)

	authed := mux.NewRouter().SkipClean(true)
	authed.NotFoundHandler = handlers.NotFound()
	authed.Use(auth.HasRole(s.config, version.Program+":agent", user.NodesGroup, bootstrapapi.BootstrapDefaultGroup))
	authed.Handle(prefix+"/serving-kubelet.crt", handlers.ServingKubeletCert(s.config, s.config.Runtime.ServingKubeletKey, nodeAuth))
	authed.Handle(prefix+"/client-kubelet.crt", handlers.ClientKubeletCert(s.config, s.config.Runtime.ClientKubeletKey, nodeAuth))
	authed.Handle(prefix+"/client-kube-proxy.crt", handlers.File(s.config.Runtime.ClientKubeProxyCert, s.config.Runtime.ClientKubeProxyKey))
	authed.Handle(prefix+"/client-{product:(?:k3s|rke2)}-controller.crt", handlers.File(s.config.Runtime.ClientK3sControllerCert, s.config.Runtime.ClientK3sControllerKey))
	authed.Handle(prefix+"/client-ca.crt", handlers.File(s.config.Runtime.ClientCA))
	authed.Handle(prefix+"/server-ca.crt", handlers.File(s.config.Runtime.ServerCA))
	authed.Handle(prefix+"/apiservers", handlers.APIServers(s.config))
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
	serverAuthed.Handle("/db/info", handlers.DBInfo(s.config))

	router := mux.NewRouter().SkipClean(true)
	router.NotFoundHandler = serverAuthed
	router.Handle("/cacerts", handlers.CACerts(s.config))
	router.Handle("/ping", handlers.Ping())

	s.router = router
	return nil
}
