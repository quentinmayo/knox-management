package platform

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quentinmayo/StepDownproxy/pkg/knox"
)

func TestAuthRedactionAndAudit(t *testing.T) {
	admin := strings.Repeat("a", 48)
	secret := strings.Repeat("s", 48)
	backendAuth := "0u" + strings.Repeat("k", 48)
	t.Setenv("TEST_MANAGEMENT_AUTH", admin)
	t.Setenv("TEST_KNOX_AUTH", backendAuth)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != backendAuth {
			t.Error("backend authorization incorrect")
		}
		if strings.HasSuffix(r.URL.Path, "/access/") {
			_, _ = w.Write([]byte(`{"status":"ok","data":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": map[string]any{"id": "test:key", "acl": []any{}, "versions": []any{map[string]any{"id": 1, "status": "Primary", "ts": 100, "data": base64.StdEncoding.EncodeToString([]byte(secret))}}}})
	}))
	defer backend.Close()
	var logs bytes.Buffer
	p, err := New(Config{Listen: "127.0.0.1:19100", AdminTokenEnv: "TEST_MANAGEMENT_AUTH", Knox: knox.Connection{URL: backend.URL, AuthEnv: "TEST_KNOX_AUTH", AllowHTTP: true}}, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	request := func(token, origin, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/command", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		return w
	}
	cmd := `{"operation":"inspect","key_id":"test:key"}`
	if request(backendAuth, "", cmd).Code != 401 {
		t.Fatal("Knox auth can administer console")
	}
	if request(admin, "https://evil.example", cmd).Code != 403 {
		t.Fatal("cross-origin command accepted")
	}
	w := request(admin, "", cmd)
	if w.Code != 200 {
		t.Fatal("inspect failed", w.Code, w.Body.String())
	}
	for _, value := range []string{secret, backendAuth, admin, base64.StdEncoding.EncodeToString([]byte(secret))} {
		if strings.Contains(w.Body.String(), value) || strings.Contains(logs.String(), value) {
			t.Fatal("credential leaked")
		}
	}
	if request(admin, "", `{"operation":"delete","key_id":"test:key"}`).Code != 400 {
		t.Fatal("unsupported deletion accepted")
	}
	if request(admin, "", `{"operation":"list","unknown":"x"}`).Code != 400 {
		t.Fatal("unknown fields accepted")
	}
	if request(admin, "", cmd+` {}`).Code != 400 {
		t.Fatal("trailing JSON accepted")
	}
	if request(admin, "", strings.Repeat("x", (64<<10)+1)).Code != 413 {
		t.Fatal("oversized request accepted")
	}
	r := httptest.NewRequest("GET", "/api/activity", nil)
	r.Header.Set("Authorization", "Bearer "+admin)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"operation":"inspect"`) {
		t.Fatal("activity missing")
	}
}

func TestCredentialSeparation(t *testing.T) {
	token := strings.Repeat("a", 48)
	t.Setenv("ADMIN", token)
	t.Setenv("KNOX", "0u"+token)
	if _, err := New(Config{AdminTokenEnv: "ADMIN", Knox: knox.Connection{URL: "https://knox.example", AuthEnv: "KNOX"}}, nil); err == nil {
		t.Fatal("credential reuse accepted")
	}
}
