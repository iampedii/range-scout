// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (api.go) implements the local HTTP API server lifecycle.
// ==============================================================================

package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"
)

type apiWriteCommand int

const (
	apiCmdStop           apiWriteCommand = iota
	apiCmdRestartSession
	apiCmdRestartProcess
)

func (c *Client) apiListenAddr() string {
	return net.JoinHostPort(c.cfg.APIListenAddress, strconv.Itoa(c.cfg.APIListenPort))
}

func (c *Client) StartAPIServer(parentCtx context.Context) {
	if !c.cfg.APIEnabled {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", c.handleStatus)
	mux.HandleFunc("/api/v1/traffic", c.handleTraffic)
	mux.HandleFunc("/api/v1/resolvers", c.handleResolvers)
	mux.HandleFunc("/api/v1/streams", c.handleStreams)
	mux.HandleFunc("/api/v1/balancer", c.handleBalancer)
	mux.HandleFunc("/api/v1/mtu", c.handleMTU)
	mux.HandleFunc("/api/v1/ping", c.handlePing)
	mux.HandleFunc("/api/v1/socks", c.handleSocks)
	mux.HandleFunc("/api/v1/version", c.handleVersion)
	mux.HandleFunc("/api/v1/stop", c.handleStop)
	mux.HandleFunc("/api/v1/restart-session", c.handleRestartSession)
	mux.HandleFunc("/api/v1/restart", c.handleRestart)

	srv := &http.Server{
		Addr:         c.apiListenAddr(),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	c.apiSrv = srv

	go func() {
		if c.log != nil {
			c.log.Infof("🌐 <cyan>API server listening on %s</cyan>", srv.Addr)
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if c.log != nil {
				c.log.Errorf("<red>API server error: %v</red>", err)
			}
		}
	}()

	go func() {
		<-parentCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
}

func (c *Client) StopAPIServer() {
	if c.apiSrv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.apiSrv.Shutdown(ctx)
	c.apiSrv = nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func restartProcess() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Start()
	os.Exit(0)
}
