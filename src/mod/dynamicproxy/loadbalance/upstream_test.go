package loadbalance

import "testing"

// Regression test: strings.HasPrefix(domain, prefix) checks whether domain starts
// with prefix, not the other way around. The scheme-detection here used to call it
// backwards (HasPrefix(prefix, domain)), which is only ever true when domain is no
// longer than the prefix itself -- for any real hostname/IP it's always false, so
// the "already has a scheme" check never fired and a scheme typed into the target
// field got a second one prepended (e.g. "https://https://192.168.120.70").
func TestBuildUpstreamTargetURLDoesNotDoublePrefixScheme(t *testing.T) {
	tests := []struct {
		name       string
		rawDomain  string
		requireTLS bool
		want       string
	}{
		{"bare host, TLS required", "192.168.120.70", true, "https://192.168.120.70"},
		{"bare host, no TLS", "192.168.120.70", false, "http://192.168.120.70"},
		{"scheme already present, TLS also checked", "https://192.168.120.70", true, "https://192.168.120.70"},
		{"scheme already present, TLS unchecked", "https://192.168.120.70", false, "https://192.168.120.70"},
		{"http scheme already present", "http://192.168.120.70", true, "http://192.168.120.70"},
		{"trailing slash is stripped before scheme detection", "192.168.120.70/", true, "https://192.168.120.70"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildUpstreamTargetURL(tc.rawDomain, tc.requireTLS)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("buildUpstreamTargetURL(%q, %v) = %q, want %q", tc.rawDomain, tc.requireTLS, got.String(), tc.want)
			}
		})
	}
}

func TestBuildUpstreamTargetURLRejectsEmptyDomain(t *testing.T) {
	if _, err := buildUpstreamTargetURL("", true); err == nil {
		t.Fatalf("expected an error for an empty domain")
	}
}
