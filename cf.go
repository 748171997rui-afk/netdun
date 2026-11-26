package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const cfAPI = "https://api.cloudflare.com/client/v4"

type CF struct {
	Email string `json:"email,omitempty"`
	Key   string `json:"key,omitempty"`
	Token string `json:"token,omitempty"`
}

type cfEnv struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

type cfAPIError struct {
	status  int
	message string
}

func (e *cfAPIError) Error() string { return e.message }

var httpc = &http.Client{Timeout: 30 * time.Second}

func (c *CF) do(method, path string, body any, out any) error {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, cfAPI+path, rd)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	} else {
		req.Header.Set("X-Auth-Email", c.Email)
		req.Header.Set("X-Auth-Key", c.Key)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("连不上 Cloudflare: %v", err)
	}
	defer resp.Body.Close()
	var env cfEnv
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("HTTP %d，返回内容解析不了", resp.StatusCode)
	}
	if !env.Success {
		var ms []string
		for _, e := range env.Errors {
			ms = append(ms, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		if len(ms) == 0 {
			ms = append(ms, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
		return &cfAPIError{status: resp.StatusCode, message: strings.Join(ms, "; ")}
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func (c *CF) Check() error {
	if c.Token == "" {
		return c.do("GET", "/user", nil, nil)
	}
	// 直接查安装时需要的区域，域名级 Token 不需要读取用户资料。
	zones, err := c.Zones()
	if err != nil {
		return err
	}
	if len(zones) == 0 {
		return errors.New("Token 看不到已激活的域名，请检查指定域名和 Zone Read 权限")
	}
	return nil
}

type cfZone struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	NS   []string `json:"name_servers"`
}

func (c *CF) Zones() ([]cfZone, error) {
	var z []cfZone
	err := c.do("GET", "/zones?per_page=50&status=active", nil, &z)
	return z, err
}

type cfRecord struct {
	ID string `json:"id"`
	DNSRecord
}

func (c *CF) DNSList(zid, name string) ([]cfRecord, error) {
	var r []cfRecord
	err := c.do("GET", "/zones/"+zid+"/dns_records?per_page=100&name="+url.QueryEscape(name), nil, &r)
	return r, err
}

func (c *CF) DNSCreate(zid string, rec DNSRecord) (string, error) {
	var r cfRecord
	err := c.do("POST", "/zones/"+zid+"/dns_records", rec, &r)
	return r.ID, err
}

func (c *CF) DNSDelete(zid, id string) error {
	return c.do("DELETE", "/zones/"+zid+"/dns_records/"+id, nil, nil)
}

// 规则集原样读出来，只增删自己那条，别人的规则不碰
func (c *CF) RulesGet(zid, phase string) ([]map[string]any, error) {
	var r struct {
		Rules []map[string]any `json:"rules"`
	}
	err := c.do("GET", "/zones/"+zid+"/rulesets/phases/"+phase+"/entrypoint", nil, &r)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return r.Rules, nil
}

// 先读两个规则集，避免只配了 DNS 的 Token 装到一半才报错。
func (c *CF) checkWSRules(zid string) error {
	for _, rule := range []struct{ phase, permission string }{
		{"http_request_origin", "Origin Rules"},
		{"http_config_settings", "Config Rules"},
	} {
		if _, err := c.RulesGet(zid, rule.phase); err != nil {
			return fmt.Errorf("读取 CF WS 规则失败，请检查目标域名的 %s Edit 权限：%w", rule.permission, err)
		}
	}
	return nil
}

func (c *CF) rulesEdit(zid, phase, desc string, add map[string]any) error {
	rules, err := c.RulesGet(zid, phase)
	if err != nil {
		return err
	}
	kept := []map[string]any{}
	found := false
	for _, r := range rules {
		if d, _ := r["description"].(string); d == desc {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if add == nil && !found {
		return nil
	}
	if add != nil {
		kept = append(kept, add)
	}
	return c.do("PUT", "/zones/"+zid+"/rulesets/phases/"+phase+"/entrypoint", map[string]any{"rules": kept}, nil)
}

func (c *CF) RuleUpsert(zid, phase, desc string, rule map[string]any) error {
	rule["description"] = desc
	rule["enabled"] = true
	return c.rulesEdit(zid, phase, desc, rule)
}

func (c *CF) RuleRemove(zid, phase, desc string) error { return c.rulesEdit(zid, phase, desc, nil) }

func (c *CF) Setting(zid, name string) string {
	var r struct {
		Value any `json:"value"`
	}
	if c.do("GET", "/zones/"+zid+"/settings/"+name, nil, &r) != nil {
		return ""
	}
	return fmt.Sprint(r.Value)
}

func (c *CF) SetSetting(zid, name string, v any) error {
	return c.do("PATCH", "/zones/"+zid+"/settings/"+name, map[string]any{"value": v}, nil)
}

// ── 凭据 ─────────────────────────────────────────────
var cfCur *CF

func cfLoad() *CF {
	b, err := os.ReadFile(cfPath)
	if err != nil {
		return nil
	}
	c := &CF{}
	if json.Unmarshal(b, c) != nil || !c.valid() {
		return nil
	}
	return c
}

func cfLogin() *CF {
	if cfCur != nil {
		return cfCur
	}
	if c := cfLoad(); c != nil {
		if err := c.Check(); err == nil {
			cfCur = c
			return c
		}
		warn("保存的 CF 账号验证不过了，重新输入一次")
	}
	return cfPrompt(loadState())
}

func (c *CF) valid() bool {
	return c.Token != "" || (c.Email != "" && c.Key != "")
}

func cfPrompt(st *State) *CF {
	for {
		info("选择 Cloudflare 凭据：1. 邮箱 + Global API Key   2. API Token")
		c := &CF{}
		if askInt("凭据类型", 1, 1, 2) == 2 {
			info("创建自定义 Token，区域资源只包含节点域名。权限选 Zone → Zone → Read、Zone → DNS → Edit")
			info("安装 CF WS 再加 Zone → Origin Rules → Edit 和 Zone → Config Rules → Edit")
			c.Token = askSecret("API Token（输入时不显示）")
		} else {
			info("登录 Cloudflare 控制台 https://dash.cloudflare.com/，点右上角头像，再点「设置」。")
			info("在左栏的 User settings 下展开「API 凭据」，点「API 密钥」。")
			info("找到 Global API key 这一行，点右边的「查看」。")
			c.Email = ask("CF 登录邮箱", "")
			c.Key = askSecret("Global API Key（输入时不显示）")
		}
		if !c.valid() {
			warn("凭据不能为空")
			continue
		}
		if err := c.Check(); err != nil {
			warn("验证失败：%v。再来一次（Ctrl+C 退出）", err)
			continue
		}
		if st.Zone != nil && (st.TLS != nil || st.WS != nil) {
			if _, err := c.DNSList(st.Zone.ID, st.Zone.Name); err != nil {
				warn("新凭据无法访问现有域名 %s 的 DNS 记录：%v", st.Zone.Name, err)
				continue
			}
			if st.WS != nil && c.Token != "" {
				if err := c.checkWSRules(st.Zone.ID); err != nil {
					warn("%v", err)
					continue
				}
			}
		}
		b, _ := json.Marshal(c)
		if err := writeFileAtomic(cfPath, b, 0600); err != nil {
			die("保存 Cloudflare 凭据失败：%v", err)
		}
		ok("Cloudflare 凭据已保存")
		cfCur = c
		return c
	}
}
