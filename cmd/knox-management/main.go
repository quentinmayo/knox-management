package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quentinmayo/StepDownproxy/pkg/knox"
	"github.com/quentinmayo/knox-management/internal/platform"
)

func main() {
	config := flag.String("config", "config.json", "configuration path")
	cert := flag.String("tls-cert", "", "console TLS certificate")
	key := flag.String("tls-key", "", "console TLS private key")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	fail := func(message string) { logger.Error(message); os.Exit(1) }
	c, err := platform.LoadConfig(*config)
	if err != nil {
		fail(err.Error())
	}
	args := flag.Args()
	if len(args) > 0 && args[0] != "serve" {
		client, err := c.Knox.New()
		if err != nil {
			fail(err.Error())
		}
		cmd := knox.Command{Operation: args[0]}
		if len(args) > 1 {
			cmd.KeyID = args[1]
		}
		if cmd.Operation == "create" || cmd.Operation == "add-version" || cmd.Operation == "set-acl" {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, (16<<10)+1))
			if err != nil || len(b) > 16<<10 {
				fail("stdin unavailable or too large")
			}
			if cmd.Operation == "set-acl" {
				if json.Unmarshal(b, &cmd.ACL) != nil {
					fail("invalid ACL JSON on stdin")
				}
			} else {
				cmd.Value = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
			}
		}
		if cmd.Operation == "set-status" {
			if len(args) != 4 {
				fail("usage: set-status KEY_ID VERSION_ID Primary|Active|Inactive")
			}
			cmd.VersionID, err = strconv.ParseUint(args[2], 10, 64)
			if err != nil {
				fail("invalid version ID")
			}
			cmd.Status = args[3]
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		result, err := client.Execute(ctx, cmd)
		if err != nil {
			fail(err.Error())
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
		return
	}
	if (*cert == "") != (*key == "") {
		fail("TLS certificate and key must be supplied together")
	}
	p, err := platform.New(c, logger)
	if err != nil {
		fail(err.Error())
	}
	server := &http.Server{Addr: c.Listen, Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errors := make(chan error, 1)
	go func() {
		logger.Info("console started", "address", c.Listen)
		if *cert != "" {
			errors <- server.ListenAndServeTLS(*cert, *key)
		} else {
			errors <- server.ListenAndServe()
		}
	}()
	select {
	case err := <-errors:
		if err != http.ErrServerClosed {
			fail("console listener failed")
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
}
