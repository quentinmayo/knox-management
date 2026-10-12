package platform

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quentinmayo/StepDownproxy/pkg/knox"
)

//go:embed web/*
var web embed.FS

type Config struct {
	Listen         string          `json:"listen"`
	AdminTokenEnv  string          `json:"admin_token_env,omitempty"`
	AdminTokenFile string          `json:"admin_token_file,omitempty"`
	Knox           knox.Connection `json:"knox"`
}

func strict(b []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return errors.New("invalid JSON fields or types")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 1<<20 {
		return c, errors.New("configuration unavailable or too large")
	}
	if err = strict(b, &c); err != nil {
		return c, err
	}
	if c.Listen == "" {
		return c, errors.New("listen required")
	}
	return c, nil
}

type Event struct {
	Time      time.Time `json:"time"`
	Operation string    `json:"operation"`
	Success   bool      `json:"success"`
}
type Platform struct {
	client *knox.Client
	hash   [32]byte
	mu     sync.Mutex
	events []Event
	logger *slog.Logger
}

func New(c Config, logger *slog.Logger) (*Platform, error) {
	if (c.AdminTokenEnv == "") == (c.AdminTokenFile == "") {
		return nil, errors.New("exactly one admin_token_env or admin_token_file required")
	}
	token := os.Getenv(c.AdminTokenEnv)
	if c.AdminTokenFile != "" {
		f, err := os.Open(c.AdminTokenFile)
		if err != nil {
			return nil, errors.New("admin credential unavailable")
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
		if err != nil {
			return nil, errors.New("admin credential unavailable")
		}
		token = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	}
	if len(token) < 32 || len(token) > 16<<10 {
		return nil, errors.New("admin credential must contain 32 to 16384 bytes")
	}
	for _, r := range token {
		if r < 33 || r > 126 {
			return nil, errors.New("invalid admin credential")
		}
	}
	client, err := c.Knox.New()
	if err != nil {
		return nil, err
	}
	knoxAuth, err := client.Authorization()
	if err != nil {
		return nil, err
	}
	if token == knoxAuth || (len(knoxAuth) > 2 && token == knoxAuth[2:]) {
		return nil, errors.New("management and Knox credentials must differ")
	}
	return &Platform{client: client, hash: sha256.Sum256([]byte(token)), logger: logger, events: []Event{}}, nil
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (p *Platform) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/style.css") {
		name := r.URL.Path[1:]
		if name == "" {
			name = "index.html"
		}
		b, _ := web.ReadFile("web/" + name)
		switch name {
		case "index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "app.js":
			w.Header().Set("Content-Type", "text/javascript")
		default:
			w.Header().Set("Content-Type", "text/css")
		}
		_, _ = w.Write(b)
		return
	}
	if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		reply(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	hash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(hash[:], p.hash[:]) != 1 {
		reply(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host || (u.Scheme != "https" && u.Scheme != "http") {
			reply(w, 403, map[string]string{"error": "cross_origin_forbidden"})
			return
		}
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		reply(w, 403, map[string]string{"error": "cross_origin_forbidden"})
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/activity" {
		p.mu.Lock()
		e := append([]Event{}, p.events...)
		p.mu.Unlock()
		reply(w, 200, e)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/api/command" {
		reply(w, 404, map[string]string{"error": "not_found"})
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	if err != nil || len(b) > 64<<10 {
		reply(w, 413, map[string]string{"error": "request_too_large"})
		return
	}
	var cmd knox.Command
	if strict(b, &cmd) != nil {
		reply(w, 400, map[string]string{"error": "invalid_command"})
		return
	}
	switch cmd.Operation {
	case "list", "inspect", "create", "add-version", "set-status", "set-acl":
	default:
		reply(w, 400, map[string]string{"error": "unknown_operation"})
		return
	}
	result, err := p.client.Execute(r.Context(), cmd)
	p.mu.Lock()
	p.events = append(p.events, Event{time.Now().UTC(), cmd.Operation, err == nil})
	if len(p.events) > 100 {
		p.events = p.events[len(p.events)-100:]
	}
	p.mu.Unlock()
	if p.logger != nil {
		p.logger.Info("knox_operation", "operation", cmd.Operation, "success", err == nil)
	}
	if err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	reply(w, 200, result)
}
