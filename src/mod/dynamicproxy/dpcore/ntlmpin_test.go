package dpcore

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func newTestReverseProxy(t *testing.T) *ReverseProxy {
	t.Helper()
	target, err := url.Parse("http://127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to parse target: %v", err)
	}
	return NewDynamicProxyCore(target, "", &DpcoreOptions{})
}

// Same client connection must always get back the exact same transport, so that
// Go's own MaxConnsPerHost:1 pooling is what guarantees backend connection reuse.
func TestGetPinnedTransportReusesSameClientConnection(t *testing.T) {
	p := newTestReverseProxy(t)

	first := p.getPinnedTransport("192.0.2.10:51000")
	second := p.getPinnedTransport("192.0.2.10:51000")

	if first != second {
		t.Fatalf("expected the same pinned transport for repeated calls with the same RemoteAddr")
	}
}

// Different client connections must never share a pinned transport, otherwise one
// client's NTLM-authenticated backend connection could leak to another client.
func TestGetPinnedTransportIsolatesDifferentClientConnections(t *testing.T) {
	p := newTestReverseProxy(t)

	a := p.getPinnedTransport("192.0.2.10:51000")
	b := p.getPinnedTransport("192.0.2.20:52000")

	if a == b {
		t.Fatalf("expected different clients to get isolated pinned transports")
	}
}

// The whole mechanism only works if the pinned transport is capped to a single
// backend connection and can't silently fall back to multiplexed HTTP/2.
func TestGetPinnedTransportConfig(t *testing.T) {
	p := newTestReverseProxy(t)

	rt := p.getPinnedTransport("192.0.2.30:53000")
	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", rt)
	}
	if tr.MaxConnsPerHost != 1 {
		t.Errorf("MaxConnsPerHost = %d, want 1", tr.MaxConnsPerHost)
	}
	if tr.ForceAttemptHTTP2 {
		t.Errorf("ForceAttemptHTTP2 = true, want false (NTLM requires HTTP/1.1)")
	}
	if tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
		t.Errorf("TLSNextProto = %v, want a non-nil empty map to fully disable h2", tr.TLSNextProto)
	}
}

// Idle pins must be evicted so a long-running Zoraxy instance doesn't leak a
// transport (and its backend socket) per client IP:port that ever connected.
func TestSweepNtlmPinsOnceEvictsIdlePins(t *testing.T) {
	p := newTestReverseProxy(t)

	rt := p.getPinnedTransport("192.0.2.40:54000")

	ntlmPinsMutex.Lock()
	pin, ok := ntlmPins["192.0.2.40:54000"]
	if !ok {
		ntlmPinsMutex.Unlock()
		t.Fatalf("expected pin to be registered")
	}
	pin.lastUsed = time.Now().Add(-2 * ntlmPinIdleTimeout)
	ntlmPinsMutex.Unlock()

	sweepNtlmPinsOnce()

	ntlmPinsMutex.Lock()
	_, stillPresent := ntlmPins["192.0.2.40:54000"]
	ntlmPinsMutex.Unlock()

	if stillPresent {
		t.Fatalf("expected stale pin to be evicted by sweep")
	}

	// A fresh call after eviction must mint a new transport rather than reuse the
	// (now closed) evicted one.
	rt2 := p.getPinnedTransport("192.0.2.40:54000")
	if rt == rt2 {
		t.Fatalf("expected a new transport to be created after eviction")
	}
}
