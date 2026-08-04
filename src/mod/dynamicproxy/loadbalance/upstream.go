package loadbalance

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
)

// buildUpstreamTargetURL resolves a configured OriginIpOrDomain (which may or may
// not already carry its own scheme) plus the RequireTLS setting into the final
// upstream URL, without ever double-prefixing a scheme the user already typed.
func buildUpstreamTargetURL(rawDomain string, requireTLS bool) (*url.URL, error) {
	//Filter the tailing slash if any
	domain := rawDomain
	if len(domain) == 0 {
		return nil, errors.New("invalid endpoint config")
	}
	if domain[len(domain)-1:] == "/" {
		domain = domain[:len(domain)-1]
	}

	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		//TLS is not hardcoded in proxy target domain
		if requireTLS {
			domain = "https://" + domain
		} else {
			domain = "http://" + domain
		}
	}

	return url.Parse(domain)
}

// StartProxy create and start a HTTP proxy using dpcore
// Example of webProxyEndpoint: https://example.com:443 or http://192.168.1.100:8080
func (u *Upstream) StartProxy() error {
	//Create a new proxy agent for this upstream
	path, err := buildUpstreamTargetURL(u.OriginIpOrDomain, u.RequireTLS)
	if err != nil {
		return err
	}

	proxy := dpcore.NewDynamicProxyCore(path, "", &dpcore.DpcoreOptions{
		IgnoreTLSVerification:   u.SkipCertValidations,
		FlushInterval:           100 * time.Millisecond,
		ResponseHeaderTimeout:   u.RespTimeout,
		MaxConcurrentConnection: u.MaxConn,
	})

	u.proxy = proxy
	return nil
}

// IsReady return the proxy ready state of the upstream server
// Return false if StartProxy() is not called on this upstream before
func (u *Upstream) IsReady() bool {
	return u.proxy != nil
}

// Clone return a new deep copy object of the identical upstream
func (u *Upstream) Clone() *Upstream {
	newUpstream := Upstream{}
	js, _ := json.Marshal(u)
	json.Unmarshal(js, &newUpstream)
	return &newUpstream
}

// ServeHTTP uses this upstream proxy router to route the current request, return the status code and error if any
func (u *Upstream) ServeHTTP(w http.ResponseWriter, r *http.Request, rrr *dpcore.ResponseRewriteRuleSet) (int, error) {
	//Auto rewrite to upstream origin if not set
	if rrr.ProxyDomain == "" {
		rrr.ProxyDomain = u.OriginIpOrDomain
	}

	return u.proxy.ServeHTTP(w, r, rrr)
}

// String return the string representations of endpoints in this upstream
func (u *Upstream) String() string {
	return u.OriginIpOrDomain
}
