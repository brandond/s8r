package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/util"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
	"k8s.io/apiserver/pkg/endpoints/request"
)

func setupTunnel(ctx context.Context, cfg *config.Control) (http.Handler, error) {
	return &tunnelServer{
		config: cfg,
		server: remotedialer.New(authorizer, loggingErrorWriter),
	}, nil
}

type tunnelServer struct {
	config *config.Control
	server *remotedialer.Server
}

func (t *tunnelServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	t.server.ServeHTTP(resp, req)
}

func authorizer(req *http.Request) (clientKey string, authed bool, err error) {
	user, ok := request.UserFrom(req.Context())
	if !ok {
		return "", false, nil
	}

	if strings.HasPrefix(user.GetName(), "system:node:") {
		return strings.TrimPrefix(user.GetName(), "system:node:"), true, nil
	}

	return "", false, nil
}
func loggingErrorWriter(rw http.ResponseWriter, req *http.Request, code int, err error) {
	logrus.Debugf("Tunnel server error: %d %v", code, err)
	util.SendError(err, rw, req, code)
}
