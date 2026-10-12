// demo-knox wraps the real Pinterest Knox router and encrypted in-memory
// database with a fake local authentication provider. Never deploy it for real
// secrets; the process loses all data on exit.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/server"
	"github.com/pinterest/knox/server/auth"
	"github.com/pinterest/knox/server/keydb"
)

type provider struct{ token string }

func (p provider) Name() string  { return "local-demo" }
func (p provider) Version() byte { return '0' }
func (p provider) Type() byte    { return 'u' }
func (p provider) Authenticate(token string, _ *http.Request) (knox.Principal, error) {
	if subtle.ConstantTimeCompare([]byte(token), []byte(p.token)) != 1 {
		return nil, errors.New("authentication denied")
	}
	return auth.NewUser("demo-operator", nil), nil
}

func main() {
	token := os.Getenv("KNOX_DEMO_AUTH")
	if !strings.HasPrefix(token, "0u") || len(token) < 34 {
		os.Exit(1)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		os.Exit(1)
	}
	router, err := server.GetRouter(keydb.NewAESGCMCryptor(0, key), keydb.NewTempDB(), []func(http.HandlerFunc) http.HandlerFunc{server.Authentication([]auth.Provider{provider{token[2:]}}, nil)}, nil)
	if err != nil {
		os.Exit(1)
	}
	s := &http.Server{Addr: ":9010", Handler: router, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second}
	if s.ListenAndServe() != http.ErrServerClosed {
		os.Exit(1)
	}
}
