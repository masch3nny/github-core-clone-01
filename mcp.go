// MCP: POST /mcp, JSON-RPC 2.0 Streamable HTTP. Modern era 2026-07-28 via
// server/discover, with the legacy initialize handshake as a fallback.
// tools/list is built once at startup and answered byte-identically.
// Tool results carry both a text JSON rendering and structuredContent; the
// suite reads structuredContent first and falls back to the text.
package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// buildToolsList renders the fixed tools array (byte-identical every call).
func buildToolsList() []byte {
	tool := func(name, desc string, props, required []string) string {
		var b strings.Builder
		b.WriteString(`{"name":`)
		b.WriteString(strconv.Quote(name))
		b.WriteString(`,"description":`)
		b.WriteString(strconv.Quote(desc))
		b.WriteString(`,"inputSchema":{"type":"object","properties":{`)
		for i := 0; i < len(props); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Quote(props[i]))
			b.WriteString(`:{"type":`)
			b.WriteString(strconv.Quote(props[i+1]))
			b.WriteString(`}`)
		}
		b.WriteString(`},"required":[`)
		for i, r := range required {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Quote(r))
		}
		b.WriteString(`]}}`)
		return b.String()
	}
	tools := []string{
		tool("create_repo", "Create a repository under the token owner.",
			[]string{"name", "string", "description", "string", "private", "boolean"},
			[]string{"name"}),
		tool("get_repo", "Get a repository by owner and name.",
			[]string{"owner", "string", "repo", "string"},
			[]string{"owner", "repo"}),
		tool("create_issue", "Create an issue in a repository.",
			[]string{"owner", "string", "repo", "string", "title", "string", "body", "string"},
			[]string{"owner", "repo", "title"}),
		tool("list_issues", "List the issues of a repository.",
			[]string{"owner", "string", "repo", "string", "state", "string"},
			[]string{"owner", "repo"}),
		tool("create_pull_request", "Open a pull request.",
			[]string{"owner", "string", "repo", "string", "title", "string", "head", "string", "base", "string"},
			[]string{"owner", "repo", "title", "head", "base"}),
		tool("merge_pull_request", "Merge a pull request.",
			[]string{"owner", "string", "repo", "string", "pull_number", "integer"},
			[]string{"owner", "repo", "pull_number"}),
	}
	return []byte("[" + strings.Join(tools, ",") + "]")
}

// mcpRoute handles POST /mcp.
func (cc *conn) mcpRoute() {
	r := &cc.req
	if r.method != "POST" {
		cc.notFound("")
		return
	}
	// A malformed body is HTTP 400 + JSON-RPC -32700.
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(r.body, &req); err != nil {
		body := []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}`)
		cc.writeResp(400, "application/json", body)
		return
	}
	// notifications/initialized carries no id: 202 with an empty body.
	if req.Method == "notifications/initialized" {
		cc.writeResp(202, "application/json", nil)
		return
	}
	id := req.ID
	if len(id) == 0 {
		id = []byte("null")
	}
	cc.store.mu.Lock()
	defer cc.store.mu.Unlock()
	switch req.Method {
	case "server/discover":
		result := []byte(`{"supportedVersions":["2026-07-28","2025-11-25"],"capabilities":{"tools":{}},"serverInfo":{"name":"forge","version":"1.0.0"},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"forge","version":"1.0.0"}}}`)
		cc.writeJSON(200, mcpEnvelope(id, result))
	case "initialize":
		version := "2025-11-25"
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &params)
			if params.ProtocolVersion != "" {
				version = params.ProtocolVersion
			}
		}
		result := []byte(`{"protocolVersion":` + strconv.Quote(version) + `,"capabilities":{"tools":{}},"serverInfo":{"name":"forge","version":"1.0.0"}}`)
		cc.writeJSON(200, mcpEnvelope(id, result))
	case "tools/list":
		result := append([]byte(`{"tools":`), cc.store.toolsList...)
		result = append(result, '}')
		cc.writeJSON(200, mcpEnvelope(id, result))
	case "tools/call":
		cc.mcpCall(id, req.Params)
	default:
		cc.writeJSON(200, mcpError(id, -32601, "method not found: "+req.Method))
	}
}

// mcpEnvelope wraps a result in a JSON-RPC 2.0 response.
func mcpEnvelope(id json.RawMessage, result []byte) []byte {
	b := make([]byte, 0, len(result)+32)
	b = append(b, `{"jsonrpc":"2.0","id":`...)
	b = append(b, id...)
	b = append(b, `,"result":`...)
	b = append(b, result...)
	b = append(b, '}')
	return b
}

// mcpError renders a JSON-RPC error response (HTTP 200).
func mcpError(id json.RawMessage, code int, msg string) []byte {
	b := make([]byte, 0, len(msg)+64)
	b = append(b, `{"jsonrpc":"2.0","id":`...)
	b = append(b, id...)
	b = append(b, `,"error":{"code":`...)
	b = strconv.AppendInt(b, int64(code), 10)
	b = append(b, `,"message":`...)
	b = appendJSONString(b, msg)
	b = append(b, `}}`...)
	return b
}

// mcpToolResult renders a tool result with text JSON + structuredContent.
func mcpToolResult(id json.RawMessage, objJSON []byte) []byte {
	b := make([]byte, 0, len(objJSON)*2+128)
	b = append(b, `{"jsonrpc":"2.0","id":`...)
	b = append(b, id...)
	b = append(b, `,"result":{"content":[{"type":"text","text":`...)
	b = appendJSONString(b, string(objJSON))
	b = append(b, `}],"structuredContent":`...)
	b = append(b, objJSON...)
	b = append(b, `}}`...)
	return b
}

// mcpToolError renders a tool result with isError true.
func mcpToolError(id json.RawMessage, msg string) []byte {
	b := make([]byte, 0, len(msg)+128)
	b = append(b, `{"jsonrpc":"2.0","id":`...)
	b = append(b, id...)
	b = append(b, `,"result":{"content":[{"type":"text","text":`...)
	b = appendJSONString(b, msg)
	b = append(b, `}],"isError":true}}`...)
	return b
}

// mcpCall executes one tools/call.
func (cc *conn) mcpCall(id json.RawMessage, rawParams json.RawMessage) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if len(rawParams) > 0 {
		if err := json.Unmarshal(rawParams, &params); err != nil {
			cc.writeJSON(200, mcpError(id, -32602, "invalid params"))
			return
		}
	}
	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}
	argStr := func(key string) string {
		if v, ok := params.Arguments[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	argInt := func(key string) int {
		if v, ok := params.Arguments[key]; ok {
			if f, ok := v.(float64); ok {
				return int(f)
			}
		}
		return 0
	}
	need := func(keys ...string) string {
		for _, k := range keys {
			if argStr(k) == "" && argInt(k) == 0 {
				return k
			}
		}
		return ""
	}
	switch params.Name {
	case "create_repo":
		if missing := need("name"); missing != "" {
			cc.writeJSON(200, mcpToolError(id, "missing required argument: "+missing))
			return
		}
		name := argStr("name")
		if cc.store.getRepo(viewerLogin, name) != nil {
			cc.writeJSON(200, mcpToolError(id, "repository already exists"))
			return
		}
		repo := cc.store.createRepo(name, argStr("private") == "true", argStr("description"))
		// private may arrive as a JSON boolean, not a string.
		if v, ok := params.Arguments["private"]; ok {
			if b, ok := v.(bool); ok {
				repo.Private = b
				repo.cached = nil
			}
		}
		cc.writeJSON(200, mcpToolResult(id, repoJSON(repo, cc.req.origin())))
	case "get_repo":
		if missing := need("owner", "repo"); missing != "" {
			cc.writeJSON(200, mcpToolError(id, "missing required argument: "+missing))
			return
		}
		owner, name := argStr("owner"), argStr("repo")
		if owner != viewerLogin {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		repo := cc.store.getRepo(owner, name)
		if repo == nil {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		cc.writeJSON(200, mcpToolResult(id, repoJSON(repo, cc.req.origin())))
	case "create_issue":
		if missing := need("owner", "repo", "title"); missing != "" {
			cc.writeJSON(200, mcpToolError(id, "missing required argument: "+missing))
			return
		}
		owner, name := argStr("owner"), argStr("repo")
		if owner != viewerLogin {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		repo := cc.store.getRepo(owner, name)
		if repo == nil {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		iss := cc.store.createIssue(repo, argStr("title"), argStr("body"), nil)
		cc.writeJSON(200, mcpToolResult(id, issueJSON(iss)))
	case "list_issues":
		if missing := need("owner", "repo"); missing != "" {
			cc.writeJSON(200, mcpToolError(id, "missing required argument: "+missing))
			return
		}
		owner, name := argStr("owner"), argStr("repo")
		if owner != viewerLogin {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		repo := cc.store.getRepo(owner, name)
		if repo == nil {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		state := argStr("state")
		b := make([]byte, 0, 512)
		b = append(b, `{"issues":[`...)
		first := true
		for _, iss := range repo.IssueOrder {
			if state != "" && state != "all" && iss.State != state {
				continue
			}
			if !first {
				b = append(b, ',')
			}
			first = false
			b = append(b, issueJSON(iss)...)
		}
		b = append(b, `]}`...)
		cc.writeJSON(200, mcpToolResult(id, b))
	case "create_pull_request":
		if missing := need("owner", "repo", "title", "head", "base"); missing != "" {
			cc.writeJSON(200, mcpToolError(id, "missing required argument: "+missing))
			return
		}
		owner, name := argStr("owner"), argStr("repo")
		if owner != viewerLogin {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		repo := cc.store.getRepo(owner, name)
		if repo == nil {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		head, base := argStr("head"), argStr("base")
		headSHA, ok := repo.Refs["refs/heads/"+head]
		if !ok {
			cc.writeJSON(200, mcpToolError(id, "head branch does not exist"))
			return
		}
		baseSHA, ok := repo.Refs["refs/heads/"+base]
		if !ok {
			cc.writeJSON(200, mcpToolError(id, "base branch does not exist"))
			return
		}
		for _, other := range repo.PROrder {
			if other.State == "open" && other.HeadRef == head {
				cc.writeJSON(200, mcpToolError(id, "a pull request already exists for "+head))
				return
			}
		}
		files := prFilesFor(repo, baseSHA, headSHA)
		pr := cc.store.createPR(repo, argStr("title"), "", head, base, headSHA, baseSHA, files)
		cc.writeJSON(200, mcpToolResult(id, prJSON(pr)))
	case "merge_pull_request":
		if missing := need("owner", "repo", "pull_number"); missing != "" {
			cc.writeJSON(200, mcpToolError(id, "missing required argument: "+missing))
			return
		}
		owner, name := argStr("owner"), argStr("repo")
		if owner != viewerLogin {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		repo := cc.store.getRepo(owner, name)
		if repo == nil {
			cc.writeJSON(200, mcpToolError(id, "repository not found"))
			return
		}
		pr := repo.PRs[argInt("pull_number")]
		if pr == nil {
			cc.writeJSON(200, mcpToolError(id, "pull request not found"))
			return
		}
		if pr.State != "open" {
			cc.writeJSON(200, mcpToolError(id, "pull request is not open"))
			return
		}
		mergeSHA, conflict := cc.store.mergePR(repo, pr)
		if conflict {
			cc.writeJSON(200, mcpToolError(id, "merge conflict"))
			return
		}
		obj := []byte(`{"sha":` + strconv.Quote(mergeSHA) + `,"merged":true,"message":"merged pull request #` + strconv.Itoa(pr.Number) + `"}`)
		cc.writeJSON(200, mcpToolResult(id, obj))
	default:
		cc.writeJSON(200, mcpError(id, -32602, "unknown tool: "+params.Name))
	}
}
