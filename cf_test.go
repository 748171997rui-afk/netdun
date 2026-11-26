package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type cfTransport func(*http.Request) (*http.Response, error)

func (f cfTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func mockCF(t *testing.T, f cfTransport) {
	t.Helper()
	old := httpc
	httpc = &http.Client{Transport: f}
	t.Cleanup(func() { httpc = old })
}

func cfResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestCFCredentials(t *testing.T) {
	for _, tc := range []struct{ name, stored, path, token string }{
		{"原有 Key 配置", `{"email":"test@example.org","key":"test-key"}`, "/user", ""},
		{"限定域名的 Token", `{"token":"test-token"}`, "/zones", "Bearer test-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c CF
			if err := json.Unmarshal([]byte(tc.stored), &c); err != nil || !c.valid() {
				t.Fatal("读取凭据失败")
			}
			mockCF(t, func(req *http.Request) (*http.Response, error) {
				if tc.token != req.Header.Get("Authorization") || c.Email != req.Header.Get("X-Auth-Email") || c.Key != req.Header.Get("X-Auth-Key") {
					t.Fatal("鉴权请求头错误")
				}
				if req.URL.Path != "/client/v4"+tc.path {
					t.Fatalf("验证路径错误：%s", req.URL.Path)
				}
				return cfResponse(200, `{"success":true,"result":[{"id":"test-zone"}]}`), nil
			})
			if err := c.Check(); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(c)
			if err != nil || string(data) != tc.stored {
				t.Fatal("凭据保存格式错误")
			}
		})
	}
}

func TestCFTokenScope(t *testing.T) {
	c := &CF{Token: "test-token"}
	mockCF(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/client/v4/zones":
			return cfResponse(200, `{"success":true,"result":[]}`), nil
		case "/client/v4/zones/z/rulesets/phases/http_request_origin/entrypoint":
			return cfResponse(403, `{"success":false,"errors":[{"code":10003,"message":"permission denied"}]}`), nil
		default:
			return cfResponse(404, `{"success":false,"errors":[{"message":"entrypoint not found"}]}`), nil
		}
	})
	if c.Check() == nil {
		t.Error("应拒绝看不到域名的 Token")
	}
	if _, err := c.RulesGet("z", "http_request_origin"); err == nil {
		t.Error("权限错误被当成空规则集")
	}
	if _, err := c.RulesGet("z", "http_config_settings"); err != nil {
		t.Errorf("规则集尚未创建：%v", err)
	}
}
