package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	upstream "github.com/pinterest/knox"
	"github.com/pinterest/knox/server"
	"github.com/pinterest/knox/server/auth"
	"github.com/pinterest/knox/server/keydb"
	"github.com/quentinmayo/StepDownproxy/pkg/knox"
	"github.com/quentinmayo/knox-management/internal/platform"
)

type testProvider struct{}

func (testProvider) Name() string  { return "integration" }
func (testProvider) Version() byte { return '0' }
func (testProvider) Type() byte    { return 'u' }
func (testProvider) Authenticate(token string, _ *http.Request) (upstream.Principal, error) {
	for _, name := range []string{"operator", "reader"} {
		if subtle.ConstantTimeCompare([]byte(token), []byte(strings.Repeat(name, 8))) == 1 {
			return auth.NewUser(name, nil), nil
		}
	}
	return nil, errors.New("authentication denied")
}

func TestRealKnoxLifecycleAndProxy(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	router, err := server.GetRouter(keydb.NewAESGCMCryptor(0, key), keydb.NewTempDB(), []func(http.HandlerFunc) http.HandlerFunc{server.Authentication([]auth.Provider{testProvider{}}, nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewTLSServer(router)
	defer backend.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LIVE_KNOX_AUTH", "0u"+strings.Repeat("operator", 8))
	t.Setenv("LIVE_ADMIN", strings.Repeat("admin", 10))
	connection := knox.Connection{URL: backend.URL, AuthEnv: "LIVE_KNOX_AUTH", CAFile: ca}
	client, err := connection.New()
	if err != nil {
		t.Fatal(err)
	}
	first := strings.Repeat("first", 10)
	second := strings.Repeat("second", 10)
	if _, err := client.Execute(ctx, knox.Command{Operation: "create", KeyID: "stepdown:github", Value: first}); err != nil {
		t.Fatal(err)
	}
	if got, err := client.ReadPrimary(ctx, "stepdown:github"); err != nil || got != first {
		t.Fatal("primary read", err)
	}
	console, err := platform.New(platform.Config{Listen: "127.0.0.1:19100", AdminTokenEnv: "LIVE_ADMIN", Knox: connection}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := func(cmd knox.Command) *httptest.ResponseRecorder {
		b, _ := json.Marshal(cmd)
		r := httptest.NewRequest("POST", "/api/command", bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+os.Getenv("LIVE_ADMIN"))
		w := httptest.NewRecorder()
		console.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("console %s: %d %s", cmd.Operation, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), first) || strings.Contains(w.Body.String(), second) {
			t.Fatal("console exposed secret")
		}
		return w
	}
	request(knox.Command{Operation: "list"})
	request(knox.Command{Operation: "inspect", KeyID: "stepdown:github"})
	if _, err := client.Execute(ctx, knox.Command{Operation: "set-acl", KeyID: "stepdown:github", ACL: []knox.Access{{Type: "User", ID: "reader", Access: "Read"}}}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LIVE_READER_AUTH", "0u"+strings.Repeat("reader", 8))
	reader, _ := (knox.Connection{URL: backend.URL, AuthEnv: "LIVE_READER_AUTH", CAFile: ca}).New()
	if _, err := reader.ReadPrimary(ctx, "stepdown:github"); err != nil {
		t.Fatal("reader cannot read", err)
	}
	if _, err := reader.Execute(ctx, knox.Command{Operation: "add-version", KeyID: "stepdown:github", Value: second}); err == nil {
		t.Fatal("read-only principal wrote a version")
	}
	var version struct {
		ID uint64 `json:"version_id,string"`
	}
	w := request(knox.Command{Operation: "add-version", KeyID: "stepdown:github", Value: second})
	if json.Unmarshal(w.Body.Bytes(), &version) != nil || version.ID == 0 {
		t.Fatal("missing new version ID")
	}
	if got, _ := client.ReadPrimary(ctx, "stepdown:github"); got != first {
		t.Fatal("Active version prematurely became Primary")
	}
	var proxyURL string
	if binary := os.Getenv("STEPDOWN_PROXY_BINARY"); binary != "" {
		proxyURL = startProxy(t, binary, backend.URL, ca, first)
	}
	checkProxy := func() {
		if proxyURL != "" {
			r, _ := http.NewRequest("GET", proxyURL+"/proxy/github/repos/example/project/issues", nil)
			r.Header.Set("Authorization", "Bearer "+os.Getenv("LIVE_CALLER"))
			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatal("proxy request failed", resp.StatusCode)
			}
		}
	}
	checkProxy()
	request(knox.Command{Operation: "set-status", KeyID: "stepdown:github", VersionID: version.ID, Status: "Primary"})
	if got, _ := client.ReadPrimary(ctx, "stepdown:github"); got != second {
		t.Fatal("rotation did not change Primary")
	}
	t.Setenv("LIVE_EXPECTED_UPSTREAM", second)
	checkProxy()
	request(knox.Command{Operation: "set-acl", KeyID: "stepdown:github", ACL: []knox.Access{{Type: "User", ID: "reader", Access: "None"}}})
	if _, err := reader.ReadPrimary(ctx, "stepdown:github"); err == nil {
		t.Fatal("revoked reader still has access")
	}
	request(knox.Command{Operation: "inspect", KeyID: "stepdown:github"})
	metadata, err := client.Execute(ctx, knox.Command{Operation: "inspect", KeyID: "stepdown:github"})
	if err != nil {
		t.Fatal(err)
	}
	if acl := metadata.(knox.Metadata).ACL; len(acl) != 1 || acl[0].ID != "operator" || acl[0].Access != "Admin" {
		t.Fatal("metadata ACL does not reflect current grants")
	}
}

func startProxy(t *testing.T, binary, knoxURL, ca, initial string) string {
	t.Helper()
	t.Setenv("LIVE_CALLER", strings.Repeat("caller", 10))
	t.Setenv("LIVE_EXPECTED_UPSTREAM", initial)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+os.Getenv("LIVE_EXPECTED_UPSTREAM") {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(api.Close)
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Input struct{ Method, Path, Principal string }
		}
		_ = json.NewDecoder(r.Body).Decode(&v)
		_ = json.NewEncoder(w).Encode(map[string]bool{"result": v.Input.Method == "GET" && v.Input.Path == "/repos/example/project/issues" && v.Input.Principal == "live-reader"})
	}))
	t.Cleanup(opa.Close)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	config := map[string]any{"listen": addr, "opa_url": opa.URL + "/v1/data/stepdown/allow", "allow_http": true, "clients": []any{map[string]any{"id": "live-reader", "token": map[string]string{"provider": "env", "ref": "LIVE_CALLER"}}}, "knox": map[string]any{"url": knoxURL, "ca_file": ca, "token": map[string]string{"provider": "env", "ref": "LIVE_KNOX_AUTH"}}, "services": []any{map[string]any{"id": "github", "url": api.URL, "header": "Authorization", "prefix": "Bearer ", "credential": map[string]string{"provider": "knox", "ref": "stepdown:github"}}}}
	b, _ := json.Marshal(config)
	path := filepath.Join(t.TempDir(), "config.json")
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("cannot write test config")
	}
	cmd := exec.Command(binary, "-config", path)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if cmd.Start() != nil {
		t.Fatal("cannot start proxy")
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
		for _, name := range []string{"LIVE_CALLER", "LIVE_KNOX_AUTH", "LIVE_EXPECTED_UPSTREAM"} {
			if strings.Contains(logs.String(), os.Getenv(name)) {
				t.Error("proxy log exposed credential")
			}
		}
	})
	url := "http://" + addr
	for i := 0; i < 50; i++ {
		resp, err := http.Get(url + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return url
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("proxy did not start")
	return ""
}
