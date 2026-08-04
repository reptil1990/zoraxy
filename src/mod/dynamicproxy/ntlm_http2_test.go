package dynamicproxy

import (
	"crypto/tls"
	"sync"
	"testing"
)

func newTestRouterWithEndpoint(hostname string, enableNTLM bool) *Router {
	r := &Router{ProxyEndpoints: &sync.Map{}}
	r.ProxyEndpoints.Store(hostname, &ProxyEndpoint{
		RootOrMatchingDomain: hostname,
		EnableNTLM:           enableNTLM,
	})
	return r
}

// NTLM's handshake needs the frontend connection pinned too, and browsers refuse
// to run NTLM over HTTP/2 at all -- so a host with EnableNTLM must not have "h2"
// offered in its ALPN, regardless of what the rest of the listener advertises.
func TestGetConfigForClientDisablesHTTP2ForNTLMHost(t *testing.T) {
	router := newTestRouterWithEndpoint("mail.example.com", true)
	base := &tls.Config{NextProtos: []string{"h2", "http/1.1"}}

	cfg, err := router.getConfigForClient(base)(&tls.ClientHelloInfo{ServerName: "mail.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected an override config for the NTLM host, got nil")
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Errorf("NextProtos = %v, want [\"http/1.1\"]", cfg.NextProtos)
	}
}

// Every other host must be untouched: returning nil tells crypto/tls to fall back
// to the listener's shared config, so HTTP/2 stays available for everyone else.
func TestGetConfigForClientLeavesOtherHostsUnchanged(t *testing.T) {
	router := newTestRouterWithEndpoint("app.example.com", false)
	base := &tls.Config{NextProtos: []string{"h2", "http/1.1"}}

	cases := []string{"app.example.com", "unregistered.example.com", ""}
	for _, sn := range cases {
		cfg, err := router.getConfigForClient(base)(&tls.ClientHelloInfo{ServerName: sn})
		if err != nil {
			t.Fatalf("unexpected error for ServerName %q: %v", sn, err)
		}
		if cfg != nil {
			t.Errorf("ServerName %q: expected nil (no override), got %+v", sn, cfg)
		}
	}
}
