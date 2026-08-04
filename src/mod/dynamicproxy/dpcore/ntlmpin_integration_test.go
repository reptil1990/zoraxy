package dpcore_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
)

// newConnRecordingBackend returns a backend whose handler records, per request,
// the RemoteAddr it saw -- i.e. which physical TCP connection from the proxy the
// request arrived on. Two requests sharing that RemoteAddr traveled over the same
// backend connection; this is exactly the identity NTLM's handshake depends on.
func newConnRecordingBackend() (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.RemoteAddr)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(seen))
		copy(out, seen)
		return out
	}
}

// get performs a real HTTP round trip and fully drains the body, which is what
// allows the underlying TCP connection to be returned to the client's keep-alive
// pool for reuse by the next call on the same *http.Client.
func get(t *testing.T, client *http.Client, url string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
}

// TestEnableNTLMPinsEachClientToItsOwnBackendConnection is an end-to-end proof of
// the actual NTLM requirement: every request belonging to one client's connection
// to the front-end must reuse the exact same backend connection, and never the
// connection belonging to another client, even though both talk to the same host.
func TestEnableNTLMPinsEachClientToItsOwnBackendConnection(t *testing.T) {
	backend, seen := newConnRecordingBackend()
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := dpcore.NewDynamicProxyCore(backendURL, "", &dpcore.DpcoreOptions{})

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r, &dpcore.ResponseRewriteRuleSet{
			ProxyDomain:  backendURL.Host,
			OriginalHost: r.Host,
			Version:      "test",
			EnableNTLM:   true,
		})
	}))
	defer front.Close()

	// Each *http.Client owns its own connection pool, i.e. its own real TCP
	// connection to the front-end -- standing in for two distinct browsers.
	clientA := &http.Client{Transport: &http.Transport{}}
	clientB := &http.Client{Transport: &http.Transport{}}
	defer clientA.Transport.(*http.Transport).CloseIdleConnections()
	defer clientB.Transport.(*http.Transport).CloseIdleConnections()

	// Interleaved like a real NTLM Type1 -> Type2 -> Type3 handshake per client,
	// with another client's requests to the same backend host interleaved between.
	get(t, clientA, front.URL)
	get(t, clientB, front.URL)
	get(t, clientA, front.URL)
	get(t, clientB, front.URL)
	get(t, clientA, front.URL)
	get(t, clientB, front.URL)

	got := seen()
	if len(got) != 6 {
		t.Fatalf("expected 6 recorded backend requests, got %d: %v", len(got), got)
	}

	aConns := []string{got[0], got[2], got[4]}
	bConns := []string{got[1], got[3], got[5]}

	if aConns[0] != aConns[1] || aConns[1] != aConns[2] {
		t.Errorf("client A's requests did not stay pinned to one backend connection: %v", aConns)
	}
	if bConns[0] != bConns[1] || bConns[1] != bConns[2] {
		t.Errorf("client B's requests did not stay pinned to one backend connection: %v", bConns)
	}
	if aConns[0] == bConns[0] {
		t.Errorf("clients A and B ended up sharing backend connection %q; an NTLM handshake would break", aConns[0])
	}
}

// TestWithoutNTLMDifferentClientsShareABackendConnection documents the bug
// EnableNTLM fixes: with the plain shared keep-alive transport, the backend
// connection handed to a request has nothing to do with which client it came
// from -- whichever connection happens to be idle gets reused next, regardless of
// origin. Two different clients making sequential requests through the same
// unpinned proxy end up sharing one backend TCP connection, which is exactly what
// breaks an in-progress NTLM handshake.
func TestWithoutNTLMDifferentClientsShareABackendConnection(t *testing.T) {
	backend, seen := newConnRecordingBackend()
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := dpcore.NewDynamicProxyCore(backendURL, "", &dpcore.DpcoreOptions{})

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r, &dpcore.ResponseRewriteRuleSet{
			ProxyDomain:  backendURL.Host,
			OriginalHost: r.Host,
			Version:      "test",
			// EnableNTLM left false: today's default, shared-pool behavior.
		})
	}))
	defer front.Close()

	clientA := &http.Client{Transport: &http.Transport{}}
	clientB := &http.Client{Transport: &http.Transport{}}
	defer clientA.Transport.(*http.Transport).CloseIdleConnections()
	defer clientB.Transport.(*http.Transport).CloseIdleConnections()

	// Strictly sequential (no concurrency needed): A's connection to the backend
	// goes idle before B's request is even sent, so B's request -- and A's next
	// one -- simply take whatever backend connection is sitting idle.
	get(t, clientA, front.URL)
	get(t, clientB, front.URL)
	get(t, clientA, front.URL)
	get(t, clientB, front.URL)

	got := seen()
	if len(got) != 4 {
		t.Fatalf("expected 4 recorded backend requests, got %d: %v", len(got), got)
	}
	for i := 1; i < len(got); i++ {
		if got[i] != got[0] {
			t.Fatalf("expected the unpinned baseline to reuse one shared backend connection across both clients, got distinct connections %v -- if this starts failing, the demonstrated bug no longer reproduces and this test should be re-evaluated before being trusted as a regression signal", got)
		}
	}
}
