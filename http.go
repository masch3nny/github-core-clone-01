// HTTP layer: a raw TCP HTTP/1.1 server (no net/http). One goroutine per
// connection, a pooled bufio.Reader per connection, a request struct reused
// across keep-alive requests, and responses assembled header+body in one
// buffer and sent with a single socket write.
package main

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
)

// request is one parsed HTTP request. It is reused across keep-alive
// requests on the same connection.
type request struct {
	method      string
	path        string // percent-decoded, without the query string
	query       string
	auth        string
	contentType string
	gitProtocol string
	accept      string
	host        string
	connection  string
	keepAlive   bool
	contentLen  int
	chunked     bool
	mcpVersion  string
	body        []byte
}

// conn is one client connection.
type conn struct {
	c     net.Conn
	br    *bufio.Reader
	store *Store
	wbuf  []byte // response assembly buffer, reused per request
	req   request
}

var statusText = map[int]string{
	200: "OK",
	201: "Created",
	202: "Accepted",
	204: "No Content",
	400: "Bad Request",
	401: "Unauthorized",
	404: "Not Found",
	405: "Method Not Allowed",
	409: "Conflict",
	422: "Unprocessable Entity",
	500: "Internal Server Error",
}

// serve accepts connections until the listener closes.
func serve(ln net.Listener, store *Store) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleConn(c, store)
	}
}

func handleConn(c net.Conn, store *Store) {
	defer c.Close()
	cc := &conn{
		c:     c,
		br:    bufio.NewReaderSize(c, 16384),
		store: store,
		wbuf:  make([]byte, 0, 16384),
	}
	for {
		if !cc.readRequest() {
			return
		}
		cc.route()
		if !cc.req.keepAlive {
			return
		}
	}
}

// readRequest parses one request from the connection. False means the
// connection is over (EOF, parse error, or a body that cannot be read).
func (cc *conn) readRequest() bool {
	r := &cc.req
	*r = request{contentLen: -1, keepAlive: true}

	line, err := cc.br.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimRight(line, "\r\n")
	// METHOD SP TARGET SP HTTP/x.y
	sp1 := strings.IndexByte(line, ' ')
	if sp1 <= 0 {
		return false
	}
	sp2 := strings.IndexByte(line[sp1+1:], ' ')
	if sp2 <= 0 {
		return false
	}
	r.method = line[:sp1]
	target := line[sp1+1 : sp1+1+sp2]
	version := line[sp1+1+sp2+1:]
	if version == "HTTP/1.0" {
		r.keepAlive = false
	}
	// Absolute-form target: strip scheme://host.
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		rest := target[strings.Index(target, "://")+3:]
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			target = rest[i:]
		} else {
			target = "/"
		}
	}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		r.path = percentDecode(target[:i])
		r.query = target[i+1:]
	} else {
		r.path = percentDecode(target)
		r.query = ""
	}

	// Headers.
	for {
		hline, err := cc.br.ReadString('\n')
		if err != nil {
			return false
		}
		hline = strings.TrimRight(hline, "\r\n")
		if hline == "" {
			break
		}
		colon := strings.IndexByte(hline, ':')
		if colon <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(hline[:colon]))
		value := strings.TrimSpace(hline[colon+1:])
		switch name {
		case "authorization":
			r.auth = value
		case "content-length":
			if n, err := strconv.Atoi(value); err == nil && n >= 0 {
				r.contentLen = n
			}
		case "content-type":
			r.contentType = value
		case "git-protocol":
			r.gitProtocol = value
		case "accept":
			r.accept = value
		case "host":
			r.host = value
		case "connection":
			r.connection = value
			lv := strings.ToLower(value)
			if strings.Contains(lv, "close") {
				r.keepAlive = false
			} else if strings.Contains(lv, "keep-alive") {
				r.keepAlive = true
			}
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(value), "chunked") {
				r.chunked = true
			}
		case "mcp-protocol-version":
			r.mcpVersion = value
		}
	}

	// Body.
	if r.chunked {
		body, ok := cc.readChunked()
		if !ok {
			return false
		}
		r.body = body
	} else if r.contentLen > 0 {
		if r.contentLen > 64<<20 {
			return false
		}
		body := make([]byte, r.contentLen)
		if _, err := io.ReadFull(cc.br, body); err != nil {
			return false
		}
		r.body = body
	} else {
		r.body = nil
	}
	return true
}

// readChunked reads a chunked transfer-encoded body.
func (cc *conn) readChunked() ([]byte, bool) {
	var body []byte
	for {
		line, err := cc.br.ReadString('\n')
		if err != nil {
			return nil, false
		}
		line = strings.TrimRight(line, "\r\n")
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		n, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
		if err != nil || n < 0 {
			return nil, false
		}
		if n == 0 {
			// Trailer headers until an empty line.
			for {
				t, err := cc.br.ReadString('\n')
				if err != nil {
					return nil, false
				}
				if strings.TrimRight(t, "\r\n") == "" {
					break
				}
			}
			return body, true
		}
		if int64(len(body))+n > 64<<20 {
			return nil, false
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(cc.br, chunk); err != nil {
			return nil, false
		}
		body = append(body, chunk...)
		// Trailing CRLF after the chunk.
		if _, err := cc.br.ReadString('\n'); err != nil {
			return nil, false
		}
	}
}

// percentDecode decodes %XX sequences; '+' is left alone (paths, not forms).
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi := hexVal(s[i+1])
			lo := hexVal(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// qval returns the value of a query parameter, or "".
func (r *request) qval(key string) string {
	q := r.query
	for len(q) > 0 {
		amp := strings.IndexByte(q, '&')
		var pair string
		if amp < 0 {
			pair, q = q, ""
		} else {
			pair, q = q[:amp], q[amp+1:]
		}
		if eq := strings.IndexByte(pair, '='); eq >= 0 {
			if pair[:eq] == key {
				return percentDecode(pair[eq+1:])
			}
		} else if pair == key {
			return ""
		}
	}
	return ""
}

// origin returns the request's origin (http://host) for absolute URLs.
func (r *request) origin() string {
	if r.host != "" {
		return "http://" + r.host
	}
	return "http://127.0.0.1"
}

// writeResp assembles status line + headers + body in one buffer and sends
// it with a single socket write.
func (cc *conn) writeResp(status int, contentType string, body []byte, extra ...string) {
	text, ok := statusText[status]
	if !ok {
		text = "Status"
	}
	b := cc.wbuf[:0]
	b = append(b, "HTTP/1.1 "...)
	b = strconv.AppendInt(b, int64(status), 10)
	b = append(b, ' ')
	b = append(b, text...)
	b = append(b, "\r\nContent-Type: "...)
	b = append(b, contentType...)
	b = append(b, "\r\nContent-Length: "...)
	b = strconv.AppendInt(b, int64(len(body)), 10)
	b = append(b, "\r\nX-GitHub-Request-Id: req-"...)
	b = strconv.AppendUint(b, cc.store.reqID.Add(1), 10)
	if cc.req.keepAlive {
		b = append(b, "\r\nConnection: keep-alive"...)
	} else {
		b = append(b, "\r\nConnection: close"...)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		b = append(b, "\r\n"...)
		b = append(b, extra[i]...)
		b = append(b, ": "...)
		b = append(b, extra[i+1]...)
	}
	b = append(b, "\r\n\r\n"...)
	b = append(b, body...)
	_, _ = cc.c.Write(b)
	cc.wbuf = b[:0]
}

// writeJSON is writeResp for application/json bodies.
func (cc *conn) writeJSON(status int, body []byte, extra ...string) {
	cc.writeResp(status, "application/json", body, extra...)
}

// unauthorized answers 401 with a JSON message body.
func (cc *conn) unauthorized() {
	cc.writeJSON(401, errorJSON("requires authentication"))
}

// notFound answers 404 with a JSON message body.
func (cc *conn) notFound(msg string) {
	if msg == "" {
		msg = "not found"
	}
	cc.writeJSON(404, errorJSON(msg))
}

// authorized reports whether the request carries the suite's bearer token.
func (s *Store) authorized(auth string) bool {
	if len(auth) < 7 || auth[:7] != "Bearer " {
		return false
	}
	tok := auth[7:]
	if tok == "" {
		return false
	}
	if s.token != "" && tok != s.token {
		return false
	}
	return true
}

// route dispatches one request to its handler.
func (cc *conn) route() {
	r := &cc.req
	path := r.path
	// A single trailing slash (other than root) is ignored.
	if len(path) > 1 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
		r.path = path
	}

	// /healthz takes no auth.
	if path == "/healthz" {
		if r.method != "GET" {
			cc.notFound("")
			return
		}
		cc.writeJSON(200, []byte(`{"ok":true}`))
		return
	}

	// Everything else needs the bearer token.
	if !cc.store.authorized(r.auth) {
		cc.unauthorized()
		return
	}

	switch {
	case path == "/api/v3" || path == "/api/v3/meta" || path == "/api/v3/user" ||
		strings.HasPrefix(path, "/api/v3/user/") || strings.HasPrefix(path, "/api/v3/repos/"):
		cc.restRoute()
	case path == "/api/graphql":
		cc.graphqlRoute()
	case path == "/mcp":
		cc.mcpRoute()
	case strings.Contains(path, ".git/"):
		cc.gitRoute()
	default:
		cc.notFound("")
	}
}
