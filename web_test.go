package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowWSRequest(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		cfRay  string
		env    string
		want   bool
	}{
		{"cf_ipv4", "104.16.1.1:44321", "", "", true},
		{"cf_ipv6", "[2606:4700::1111]:44321", "", "", true},
		{"loopback", "127.0.0.1:54321", "", "", true},
		{"nat_10_with_cfray", "10.91.2.1:51234", "a60d8117fa624e8b-SIN", "", true},
		{"nat_172_with_cfray", "172.17.0.1:51234", "a60d8117fa624e8b-SIN", "", true},
		{"nat_192_with_cfray", "192.168.1.1:51234", "a60d8117fa624e8b-SIN", "", true},
		{"cgnat_with_cfray", "100.64.0.1:51234", "a60d8117fa624e8b-SIN", "", true},
		{"nat_without_cfray", "10.91.2.1:51234", "", "", false},
		{"public_scanner", "8.8.8.8:12345", "", "", false},
		{"public_with_cfray_default_deny", "8.8.8.8:12345", "fake-ray", "", false},
		{"public_with_cfray_env_allow", "8.8.8.8:12345", "fake-ray", "1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DUN_WS_TRUST_CF_HEADER", tc.env)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			if tc.cfRay != "" {
				req.Header.Set("CF-Ray", tc.cfRay)
			}
			if got := allowWSRequest(req); got != tc.want {
				t.Errorf("allowWSRequest(%s, cfRay=%q, env=%q) = %v, want %v", tc.remote, tc.cfRay, tc.env, got, tc.want)
			}
		})
	}
}
