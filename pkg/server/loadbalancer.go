package server

import "github.com/k3s-io/k3s/pkg/agent/loadbalancer"

func (s *Server) setupLoadBalancers() error {
	var err error

	s.apiserver, err = loadbalancer.New(s.ctx, s.DataDir, loadbalancer.APIServerServiceName, "https://127.0.0.1:6443", 6443, false)
	if err != nil {
		return err
	}

	s.etcd, err = loadbalancer.New(s.ctx, s.DataDir, loadbalancer.ETCDServerServiceName, "https://127.0.0.1:2379", 2379, false)
	if err != nil {
		return err
	}

	return nil
}
