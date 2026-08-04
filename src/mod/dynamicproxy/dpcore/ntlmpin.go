package dpcore

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// NTLM/Kerberos require the client<->backend TCP connection to stay pinned for the
// whole handshake, which the shared pooled transport does not guarantee. For requests
// with EnableNTLM set, each client connection (identified by its RemoteAddr, stable
// for the connection's lifetime) gets its own transport capped to a single backend
// connection, so Go's own pooling always hands back the same one.

const (
	ntlmPinIdleTimeout = 3 * time.Minute
	ntlmPinSweepPeriod = 1 * time.Minute
)

type ntlmPinnedConn struct {
	transport *http.Transport
	lastUsed  time.Time
}

var (
	ntlmPins      = map[string]*ntlmPinnedConn{}
	ntlmPinsMutex sync.Mutex
	ntlmSweepOnce sync.Once
)

// getPinnedTransport returns the transport pinned to remoteAddr, creating it on
// first use. requestHost is only consulted at creation time: for IP-addressed
// HTTPS upstreams (p.useRequestHostAsSNI, see NewDynamicProxyCore) the shared
// base transport carries no SNI, so it's derived here from the first request's
// Host once and baked into the pin -- not re-derived per request, since that
// would require cloning (and thus a fresh, unpooled transport) on every call.
func (p *ReverseProxy) getPinnedTransport(remoteAddr, requestHost string) http.RoundTripper {
	ntlmSweepOnce.Do(startNtlmPinSweeper)

	ntlmPinsMutex.Lock()
	defer ntlmPinsMutex.Unlock()

	pin, ok := ntlmPins[remoteAddr]
	if !ok {
		base, ok := p.Transport.(*http.Transport)
		if !ok {
			return p.Transport
		}
		trc := base.Clone()
		trc.MaxConnsPerHost = 1
		trc.MaxIdleConnsPerHost = 1
		trc.IdleConnTimeout = ntlmPinIdleTimeout
		trc.ForceAttemptHTTP2 = false
		trc.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)

		if p.useRequestHostAsSNI {
			serverName := requestHost
			if h, _, err := net.SplitHostPort(serverName); err == nil {
				serverName = h
			}
			// Skip if empty or itself an IP (Go would omit an IP from the ClientHello).
			if serverName != "" && net.ParseIP(serverName) == nil {
				cfg := &tls.Config{}
				if trc.TLSClientConfig != nil {
					cfg = trc.TLSClientConfig.Clone()
				}
				cfg.ServerName = serverName
				trc.TLSClientConfig = cfg
			}
		}

		pin = &ntlmPinnedConn{transport: trc}
		ntlmPins[remoteAddr] = pin
	}
	pin.lastUsed = time.Now()
	return pin.transport
}

func startNtlmPinSweeper() {
	go func() {
		for range time.Tick(ntlmPinSweepPeriod) {
			sweepNtlmPinsOnce()
		}
	}()
}

func sweepNtlmPinsOnce() {
	ntlmPinsMutex.Lock()
	defer ntlmPinsMutex.Unlock()
	for addr, pin := range ntlmPins {
		if time.Since(pin.lastUsed) > ntlmPinIdleTimeout {
			pin.transport.CloseIdleConnections()
			delete(ntlmPins, addr)
		}
	}
}
