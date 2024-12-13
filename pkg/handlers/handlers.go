package handlers

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/brandond/s8r/pkg/auth/nodepassword"
	"github.com/brandond/s8r/pkg/version"
	"github.com/k3s-io/k3s/pkg/bootstrap"
	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/etcd"
	"github.com/k3s-io/k3s/pkg/util"
	"github.com/pkg/errors"
	certutil "github.com/rancher/dynamiclistener/cert"
	"go.etcd.io/etcd/api/v3/etcdserverpb"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/kubectl/pkg/scheme"
)

type ETCDMemberGetter func(ctx context.Context, remoteAddr string) []*etcdserverpb.Member
type APIServerAddressGetter func(ctx context.Context) []string

func CACerts(config *config.Control) http.Handler {
	var ca []byte
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if ca == nil {
			var err error
			ca, err = os.ReadFile(config.Runtime.ServerCA)
			if err != nil {
				util.SendError(err, resp, req)
				return
			}
		}
		resp.Header().Set("content-type", "text/plain")
		resp.Write(ca)
	})
}

func Ping() http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		data := []byte("pong")
		resp.WriteHeader(http.StatusOK)
		resp.Header().Set("Content-Type", "text/plain")
		resp.Header().Set("Content-Length", strconv.Itoa(len(data)))
		resp.Write(data)
	})
}

func NotFound() http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		resp.Header().Add("Connection", "close")
		serr := apierrors.NewNotFound(schema.GroupResource{}, req.URL.Path)
		responsewriters.ErrorNegotiated(serr, scheme.Codecs.WithoutConversion(), schema.GroupVersion{}, resp, req)
	})
}

func ServingKubeletCert(server *config.Control, keyFile string, auth nodepassword.NodeAuthValidator) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		nodeName, errCode, err := auth(req)
		if err != nil {
			util.SendError(err, resp, req, errCode)
			return
		}

		caCerts, caKey, key, err := getCACertAndKeys(server.Runtime.ServerCA, server.Runtime.ServerCAKey, server.Runtime.ServingKubeletKey)
		if err != nil {
			util.SendError(err, resp, req)
			return
		}

		ips := []net.IP{net.ParseIP("127.0.0.1")}

		if nodeIP := req.Header.Get(version.Program + "-Node-IP"); nodeIP != "" {
			for _, v := range strings.Split(nodeIP, ",") {
				ip := net.ParseIP(v)
				if ip == nil {
					util.SendError(fmt.Errorf("invalid node IP address %s", ip), resp, req)
					return
				}
				ips = append(ips, ip)
			}
		}

		cert, err := certutil.NewSignedCert(certutil.Config{
			CommonName: nodeName,
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AltNames: certutil.AltNames{
				DNSNames: []string{nodeName, "localhost"},
				IPs:      ips,
			},
		}, key, caCerts[0], caKey)
		if err != nil {
			util.SendError(err, resp, req)
			return
		}

		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}

		resp.Write(util.EncodeCertsPEM(cert, caCerts))
		resp.Write(keyBytes)
	})
}

func ClientKubeletCert(server *config.Control, keyFile string, auth nodepassword.NodeAuthValidator) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		nodeName, errCode, err := auth(req)
		if err != nil {
			util.SendError(err, resp, req, errCode)
			return
		}

		caCerts, caKey, key, err := getCACertAndKeys(server.Runtime.ClientCA, server.Runtime.ClientCAKey, server.Runtime.ClientKubeletKey)
		if err != nil {
			util.SendError(err, resp, req)
			return
		}

		cert, err := certutil.NewSignedCert(certutil.Config{
			CommonName:   "system:node:" + nodeName,
			Organization: []string{user.NodesGroup},
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, key, caCerts[0], caKey)
		if err != nil {
			util.SendError(err, resp, req)
			return
		}

		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}

		resp.Write(util.EncodeCertsPEM(cert, caCerts))
		resp.Write(keyBytes)
	})
}

func File(fileName ...string) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		resp.Header().Set("Content-Type", "text/plain")

		if len(fileName) == 1 {
			http.ServeFile(resp, req, fileName[0])
			return
		}

		for _, f := range fileName {
			bytes, err := os.ReadFile(f)
			if err != nil {
				util.SendError(errors.Wrapf(err, "failed to read %s", f), resp, req, http.StatusInternalServerError)
				return
			}
			resp.Write(bytes)
		}
	})
}

func APIServers(server *config.Control, getEndpoints APIServerAddressGetter) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		endpoints := getEndpoints(req.Context())
		resp.Header().Set("content-type", "application/json")
		if err := json.NewEncoder(resp).Encode(endpoints); err != nil {
			util.SendError(errors.Wrap(err, "failed to encode apiserver endpoints"), resp, req, http.StatusInternalServerError)
		}
	})
}

func Config(server *config.Control, _ *cmds.Server) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		resp.Header().Set("content-type", "application/json")
		if err := json.NewEncoder(resp).Encode(server); err != nil {
			util.SendError(errors.Wrap(err, "failed to encode agent config"), resp, req, http.StatusInternalServerError)
		}
	})
}

func Readyz(_ *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		data := []byte("ok")
		resp.WriteHeader(http.StatusOK)
		resp.Header().Set("Content-Type", "text/plain")
		resp.Header().Set("Content-Length", strconv.Itoa(len(data)))
		resp.Write(data)
	})
}

func Bootstrap(config *config.Control) http.Handler {
	return bootstrap.Handler(&config.Runtime.ControlRuntimeBootstrap)
}

func DBInfo(config *config.Control, getMembers ETCDMemberGetter) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			util.SendError(fmt.Errorf("method not allowed"), resp, req, http.StatusMethodNotAllowed)
			return
		}

		members := getMembers(req.Context(), req.RemoteAddr)
		resp.Header().Set("Content-Type", "application/json")
		json.NewEncoder(resp).Encode(&etcd.Members{
			Members: members,
		})
	})
}

func getCACertAndKeys(caCertFile, caKeyFile, signingKeyFile string) ([]*x509.Certificate, crypto.Signer, crypto.Signer, error) {
	keyBytes, err := os.ReadFile(signingKeyFile)
	if err != nil {
		return nil, nil, nil, err
	}

	key, err := certutil.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	caKeyBytes, err := os.ReadFile(caKeyFile)
	if err != nil {
		return nil, nil, nil, err
	}

	caKey, err := certutil.ParsePrivateKeyPEM(caKeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	caBytes, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, nil, nil, err
	}

	caCert, err := certutil.ParseCertsPEM(caBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return caCert, caKey.(crypto.Signer), key.(crypto.Signer), nil
}
