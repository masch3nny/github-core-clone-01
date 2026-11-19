// Entry point: the forge owns the suite lifecycle. It binds an ephemeral
// port, POSTs {"port": n} to $MAKEFUN_ENV_URL/register, serves the forge,
// and long-polls GET $MAKEFUN_ENV_URL/done until the suite is over, then
// exits 0.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	runtime.GOMAXPROCS(2)
	envURL := strings.TrimRight(os.Getenv("MAKEFUN_ENV_URL"), "/")
	token := os.Getenv("MAKEFUN_SHOP_TOKEN")
	trialNow := parseTrialNow(os.Getenv("MAKEFUN_TRIAL_NOW"))
	store := newStore(token, trialNow)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "forge: listen:", err)
		os.Exit(1)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go serve(ln, store)

	if envURL == "" {
		fmt.Fprintln(os.Stderr, "forge: MAKEFUN_ENV_URL is not set")
		os.Exit(1)
	}
	registered := false
	for i := 0; i < 100; i++ {
		if register(envURL, port) {
			registered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !registered {
		fmt.Fprintln(os.Stderr, "forge: register failed")
		os.Exit(1)
	}

	// Poll /done until the suite is over; also exit cleanly on a signal.
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	done := make(chan struct{})
	go func() {
		for {
			if pollDone(envURL) {
				close(done)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	select {
	case <-done:
	case <-sig:
	}
	os.Exit(0)
}

// parseTrialNow parses MAKEFUN_TRIAL_NOW (RFC 3339 or epoch milliseconds;
// epoch seconds are normalized to milliseconds). The fallback is the
// scenario's fixed default timestamp.
func parseTrialNow(s string) int64 {
	const fallback = 1700000000000
	if s == "" {
		return fallback
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 1000000000000 {
			return n * 1000
		}
		return n
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UnixMilli()
	}
	return fallback
}

// register POSTs {"port": n} to the env; the first register wins.
func register(envURL string, port int) bool {
	body := []byte(`{"port":` + strconv.Itoa(port) + `}`)
	req, err := http.NewRequest("POST", envURL+"/register", bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// 200: accepted. 409: another register already won (defensive: the env
	// recorded an entry; keep polling rather than dying).
	return resp.StatusCode == 200 || resp.StatusCode == 409
}

// pollDone GETs /done; true once the suite has written its export.
func pollDone(envURL string) bool {
	resp, err := http.Get(envURL + "/done")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var m struct {
		Done bool `json:"done"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return false
	}
	return m.Done
}
