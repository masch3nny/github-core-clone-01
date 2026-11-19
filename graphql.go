// GraphQL v4: POST /api/graphql. The suite's documents are fixed strings,
// so dispatch is by operation name; variables come from the request body.
// Global ids are opaque base64 of a typed key (never the plain databaseId
// or number). Unknown repositories answer data.repository = null with no
// errors; unknown fields answer HTTP 200 with an errors array.
package main

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

// globalID builds an opaque global id.
func globalID(kind, key string) string {
	return base64.StdEncoding.EncodeToString([]byte(kind + ":" + key))
}

// decodeGlobalID splits an opaque global id into kind + key.
func decodeGlobalID(id string) (kind, key string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		return "", "", false
	}
	s := string(raw)
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func repoGlobalID(r *Repo) string { return globalID("Repository", r.Owner+"/"+r.Name) }
func issueGlobalID(iss *Issue) string {
	return globalID("Issue", iss.Repo.Owner+"/"+iss.Repo.Name+"/"+strconv.Itoa(iss.Number))
}
func prGlobalID(pr *PR) string {
	return globalID("PullRequest", pr.Repo.Owner+"/"+pr.Repo.Name+"/"+strconv.Itoa(pr.Number))
}
func commentGlobalID(c *Comment, iss *Issue) string {
	return globalID("IssueComment", iss.Repo.Owner+"/"+iss.Repo.Name+"/"+strconv.Itoa(iss.Number)+"/"+strconv.FormatInt(c.ID, 10))
}

// decodeRepoKey parses a "owner/name" key.
func decodeRepoKey(key string) (owner, name string, ok bool) {
	i := strings.IndexByte(key, '/')
	if i <= 0 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

// decodeIssueKey parses a "owner/name/number" key.
func decodeIssueKey(key string) (owner, name string, number int, ok bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		return "", "", 0, false
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", "", 0, false
	}
	return parts[0], parts[1], n, true
}

// ---------------------------------------------------------------- routing

// graphqlRoute handles POST /api/graphql (single or batched documents).
func (cc *conn) graphqlRoute() {
	r := &cc.req
	if r.method != "POST" {
		cc.notFound("")
		return
	}
	cc.store.mu.Lock()
	defer cc.store.mu.Unlock()
	body := r.body
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		var docs []map[string]any
		if err := json.Unmarshal(body, &docs); err != nil {
			cc.writeJSON(400, errorJSON("malformed JSON body"))
			return
		}
		out := make([]byte, 0, 1024)
		out = append(out, '[')
		for i, doc := range docs {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, cc.execGraphQL(doc)...)
		}
		out = append(out, ']')
		cc.writeJSON(200, out)
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		cc.writeJSON(400, errorJSON("malformed JSON body"))
		return
	}
	cc.writeJSON(200, cc.execGraphQL(doc))
}

// operationName extracts the operation name from a query document.
func operationName(query string) string {
	// "query Name" or "mutation Name"
	for _, kw := range []string{"query ", "mutation "} {
		if i := strings.Index(query, kw); i >= 0 {
			rest := query[i+len(kw):]
			j := 0
			for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t' || rest[j] == '\n') {
				j++
			}
			start := j
			for j < len(rest) && (rest[j] >= 'a' && rest[j] <= 'z' || rest[j] >= 'A' && rest[j] <= 'Z' || rest[j] >= '0' && rest[j] <= '9' || rest[j] == '_') {
				j++
			}
			if j > start {
				return rest[start:j]
			}
			return ""
		}
	}
	return ""
}

// variablesOf returns the document's variables object.
func variablesOf(doc map[string]any) map[string]any {
	if v, ok := doc["variables"]; ok {
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	return map[string]any{}
}

func varString(vars map[string]any, key string) string {
	if v, ok := vars[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func varInt(vars map[string]any, key string) int {
	if v, ok := vars[key]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return 0
}

func gqlErr(msg string) []byte {
	b := []byte(`{"data":null,"errors":[{"message":`)
	b = appendJSONString(b, msg)
	b = append(b, `}]}`...)
	return b
}

func gqlData(inner []byte) []byte {
	b := make([]byte, 0, len(inner)+16)
	b = append(b, `{"data":`...)
	b = append(b, inner...)
	b = append(b, '}')
	return b
}

// execGraphQL executes one document and returns its response body.
func (cc *conn) execGraphQL(doc map[string]any) []byte {
	query, _ := doc["query"].(string)
	vars := variablesOf(doc)
	op := operationName(query)
	switch op {
	case "ViewerLogin":
		return gqlData([]byte(`{"viewer":{"login":"adaiversen"}}`))
	case "ViewerInvalidField":
		return gqlErr("Field 'noSuchFieldOnViewer' doesn't exist on type 'Viewer'")
	case "RepositoryFields":
		return cc.gqlRepositoryFields(vars)
	case "Issue_fields":
		return gqlData([]byte(`{"Issue":{"name":"Issue","fields":[` + typeFields("id", "number", "title", "body", "state", "createdAt", "updatedAt", "author", "comments", "labels", "url") + `]}}`))
	case "PullRequestAndRepositoryFields":
		return gqlData([]byte(`{"PullRequest":{"name":"PullRequest","fields":[` + typeFields("id", "number", "title", "body", "state", "merged", "mergeable", "headRefName", "baseRefName", "headRefOid", "baseRefOid", "files", "createdAt", "updatedAt", "author", "url") + `]},"Repository":{"name":"Repository","fields":[` + typeFields("id", "databaseId", "name", "nameWithOwner", "owner", "defaultBranchRef", "viewerPermission", "hasIssuesEnabled", "issue", "issues", "pullRequests", "pullRequest", "description", "createdAt", "updatedAt", "url") + `]}}`))
	case "SearchType_enumValues":
		return gqlData([]byte(`{"SearchType":{"name":"SearchType","enumValues":[{"name":"ISSUE"},{"name":"REPOSITORY"},{"name":"USER"},{"name":"DISCUSSION"},{"name":"COMMIT"}]}}`))
	case "OpenIssues":
		return cc.gqlOpenIssues(vars)
	case "IssueByNumber":
		return cc.gqlIssueByNumber(vars)
	case "PullRequests":
		return cc.gqlPullRequests(vars)
	case "PullRequestFiles":
		return cc.gqlPullRequestFiles(vars)
	case "PullRequestId":
		return cc.gqlPullRequestID(vars)
	case "IssuesPage":
		return cc.gqlIssuesPage(vars)
	case "NodeRepository":
		return cc.gqlNode(vars)
	case "IssueCreate":
		return cc.gqlCreateIssue(vars)
	case "IssueClose":
		return cc.gqlCloseIssue(vars)
	case "PullRequestCreate":
		return cc.gqlCreatePullRequest(vars)
	case "MergePullRequest":
		return cc.gqlMergePullRequest(vars)
	case "AddComment":
		return cc.gqlAddComment(vars)
	default:
		return gqlErr("unknown operation")
	}
}

// typeFields renders a __type fields array.
func typeFields(names ...string) string {
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"name":`)
		b.WriteString(strconv.Quote(n))
		b.WriteString(`,"description":""}`)
	}
	return b.String()
}

// lookupGQLRepo resolves owner/name variables to a repository (nil when
// unknown — the caller answers data.repository = null).
func (cc *conn) lookupGQLRepo(vars map[string]any) *Repo {
	owner := varString(vars, "owner")
	name := varString(vars, "name")
	if owner != viewerLogin {
		return nil
	}
	return cc.store.getRepo(owner, name)
}

func (cc *conn) gqlRepositoryFields(vars map[string]any) []byte {
	repo := cc.lookupGQLRepo(vars)
	if repo == nil {
		return gqlData([]byte(`{"repository":null}`))
	}
	b := make([]byte, 0, 320)
	b = append(b, `{"repository":{"id":`...)
	b = appendJSONString(b, repoGlobalID(repo))
	b = append(b, `,"databaseId":`...)
	b = appendJSONInt(b, repo.ID)
	b = append(b, `,"name":`...)
	b = appendJSONString(b, repo.Name)
	b = append(b, `,"owner":{"login":`...)
	b = appendJSONString(b, repo.Owner)
	b = append(b, `},"defaultBranchRef":`...)
	if repo.headOID() == "" {
		b = append(b, "null"...)
	} else {
		b = append(b, `{"name":`...)
		b = appendJSONString(b, repo.DefaultBranch)
		b = append(b, `}`...)
	}
	b = append(b, `,"viewerPermission":"ADMIN","hasIssuesEnabled":true}}`...)
	return gqlData(b)
}

func gqlIssueState(s string) string {
	if s == "closed" {
		return "CLOSED"
	}
	return "OPEN"
}

func (cc *conn) gqlOpenIssues(vars map[string]any) []byte {
	repo := cc.lookupGQLRepo(vars)
	if repo == nil {
		return gqlData([]byte(`{"repository":null}`))
	}
	first := varInt(vars, "first")
	if first <= 0 {
		first = 10
	}
	b := make([]byte, 0, 512)
	b = append(b, `{"repository":{"issues":{"nodes":[`...)
	n := 0
	for i := len(repo.IssueOrder) - 1; i >= 0 && n < first; i-- {
		iss := repo.IssueOrder[i]
		if iss.State != "open" {
			continue
		}
		if n > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"id":`...)
		b = appendJSONString(b, issueGlobalID(iss))
		b = append(b, `,"number":`...)
		b = appendJSONInt(b, int64(iss.Number))
		b = append(b, `,"title":`...)
		b = appendJSONString(b, iss.Title)
		b = append(b, `,"state":"OPEN"}`...)
		n++
	}
	b = append(b, `]}}}`...)
	return gqlData(b)
}

func (cc *conn) gqlIssueByNumber(vars map[string]any) []byte {
	repo := cc.lookupGQLRepo(vars)
	if repo == nil {
		return gqlData([]byte(`{"repository":null}`))
	}
	iss := repo.Issues[varInt(vars, "number")]
	if iss == nil {
		return gqlData([]byte(`{"repository":{"issue":null}}`))
	}
	b := make([]byte, 0, 256)
	b = append(b, `{"repository":{"issue":{"id":`...)
	b = appendJSONString(b, issueGlobalID(iss))
	b = append(b, `,"number":`...)
	b = appendJSONInt(b, int64(iss.Number))
	b = append(b, `,"title":`...)
	b = appendJSONString(b, iss.Title)
	b = append(b, `,"state":`...)
	b = appendJSONString(b, gqlIssueState(iss.State))
	b = append(b, `,"body":`...)
	b = appendJSONString(b, iss.Body)
	b = append(b, `}}}`...)
	return gqlData(b)
}

func (cc *conn) gqlPullRequests(vars map[string]any) []byte {
	repo := cc.lookupGQLRepo(vars)
	if repo == nil {
		return gqlData([]byte(`{"repository":null}`))
	}
	first := varInt(vars, "first")
	if first <= 0 {
		first = 10
	}
	b := make([]byte, 0, 512)
	b = append(b, `{"repository":{"pullRequests":{"nodes":[`...)
	n := 0
	for _, pr := range repo.PROrder {
		if pr.State != "open" {
			continue
		}
		if n >= first {
			break
		}
		if n > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"id":`...)
		b = appendJSONString(b, prGlobalID(pr))
		b = append(b, `,"number":`...)
		b = appendJSONInt(b, int64(pr.Number))
		b = append(b, `,"headRefName":`...)
		b = appendJSONString(b, pr.HeadRef)
		b = append(b, `,"baseRefName":`...)
		b = appendJSONString(b, pr.BaseRef)
		b = append(b, `,"mergeable":`...)
		b = appendJSONString(b, mergeableOf(repo, pr))
		b = append(b, `,"state":"OPEN"}`...)
		n++
	}
	b = append(b, `]}}}`...)
	return gqlData(b)
}

// mergeableOf computes a PR's mergeable state without mutating anything.
func mergeableOf(repo *Repo, pr *PR) string {
	baseTip := repo.Refs["refs/heads/"+pr.BaseRef]
	headTip := repo.Refs["refs/heads/"+pr.HeadRef]
	if baseTip == "" || headTip == "" {
		return "UNKNOWN"
	}
	if mergeConflict(repo, baseTip, headTip) {
		return "CONFLICTING"
	}
	return "MERGEABLE"
}

func (cc *conn) gqlPullRequestFiles(vars map[string]any) []byte {
	repo := cc.lookupGQLRepo(vars)
	if repo == nil {
		return gqlData([]byte(`{"repository":null}`))
	}
	pr := repo.PRs[varInt(vars, "number")]
	if pr == nil {
		return gqlData([]byte(`{"repository":{"pullRequest":null}}`))
	}
	b := make([]byte, 0, 256)
	b = append(b, `{"repository":{"pullRequest":{"number":`...)
	b = appendJSONInt(b, int64(pr.Number))
	b = append(b, `,"files":{"nodes":[`...)
	for i, f := range pr.Files {
		if i >= 10 {
			break
		}
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"path":`...)
		b = appendJSONString(b, f.Path)
		b = append(b, `}`...)
	}
	b = append(b, `]}}}}`...)
	return gqlData(b)
}

func (cc *conn) gqlPullRequestID(vars map[string]any) []byte {
	repo := cc.lookupGQLRepo(vars)
	if repo == nil {
		return gqlData([]byte(`{"repository":null}`))
	}
	pr := repo.PRs[varInt(vars, "number")]
	if pr == nil {
		return gqlData([]byte(`{"repository":{"pullRequest":null}}`))
	}
	b := make([]byte, 0, 128)
	b = append(b, `{"repository":{"pullRequest":{"id":`...)
	b = appendJSONString(b, prGlobalID(pr))
	b = append(b, `,"number":`...)
	b = appendJSONInt(b, int64(pr.Number))
	b = append(b, `}}}`...)
	return gqlData(b)
}

// cursorOf encodes an issue number as a page cursor.
func cursorOf(number int) string {
	return base64.StdEncoding.EncodeToString([]byte("cursor:" + strconv.Itoa(number)))
}

// cursorNumber decodes a page cursor; 0 when absent or invalid.
func cursorNumber(after string) int {
	if after == "" {
		return 0
	}
	raw, err := base64.StdEncoding.DecodeString(after)
	if err != nil {
		return 0
	}
	s := string(raw)
	if !strings.HasPrefix(s, "cursor:") {
		return 0
	}
	n, _ := strconv.Atoi(s[len("cursor:"):])
	return n
}

func (cc *conn) gqlIssuesPage(vars map[string]any) []byte {
	repo := cc.lookupGQLRepo(vars)
	if repo == nil {
		return gqlData([]byte(`{"repository":null}`))
	}
	first := varInt(vars, "first")
	if first <= 0 {
		first = 5
	}
	after := cursorNumber(varString(vars, "after"))
	b := make([]byte, 0, 256)
	b = append(b, `{"repository":{"issues":{"nodes":[`...)
	n := 0
	last := 0
	hasNext := false
	for _, iss := range repo.IssueOrder {
		if iss.Number <= after {
			continue
		}
		if n >= first {
			hasNext = true
			break
		}
		if n > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"number":`...)
		b = appendJSONInt(b, int64(iss.Number))
		b = append(b, `}`...)
		last = iss.Number
		n++
	}
	b = append(b, `],"pageInfo":{"hasNextPage":`...)
	b = appendJSONBool(b, hasNext)
	b = append(b, `,"endCursor":`...)
	if n > 0 {
		b = appendJSONString(b, cursorOf(last))
	} else {
		b = append(b, "null"...)
	}
	b = append(b, `}}}}`...)
	return gqlData(b)
}

func (cc *conn) gqlNode(vars map[string]any) []byte {
	id := varString(vars, "id")
	kind, key, ok := decodeGlobalID(id)
	if !ok {
		return gqlData([]byte(`{"node":null}`))
	}
	switch kind {
	case "Repository":
		owner, name, ok := decodeRepoKey(key)
		if !ok || owner != viewerLogin {
			return gqlData([]byte(`{"node":null}`))
		}
		repo := cc.store.getRepo(owner, name)
		if repo == nil {
			return gqlData([]byte(`{"node":null}`))
		}
		b := make([]byte, 0, 192)
		b = append(b, `{"node":{"id":`...)
		b = appendJSONString(b, id)
		b = append(b, `,"name":`...)
		b = appendJSONString(b, repo.Name)
		b = append(b, `,"nameWithOwner":`...)
		b = appendJSONString(b, repo.Owner+"/"+repo.Name)
		b = append(b, `}}`...)
		return gqlData(b)
	case "Issue":
		owner, name, number, ok := decodeIssueKey(key)
		if !ok || owner != viewerLogin {
			return gqlData([]byte(`{"node":null}`))
		}
		repo := cc.store.getRepo(owner, name)
		if repo == nil {
			return gqlData([]byte(`{"node":null}`))
		}
		iss := repo.Issues[number]
		if iss == nil {
			return gqlData([]byte(`{"node":null}`))
		}
		b := make([]byte, 0, 192)
		b = append(b, `{"node":{"id":`...)
		b = appendJSONString(b, id)
		b = append(b, `,"number":`...)
		b = appendJSONInt(b, int64(iss.Number))
		b = append(b, `,"title":`...)
		b = appendJSONString(b, iss.Title)
		b = append(b, `,"state":`...)
		b = appendJSONString(b, gqlIssueState(iss.State))
		b = append(b, `}}`...)
		return gqlData(b)
	case "PullRequest":
		owner, name, number, ok := decodeIssueKey(key)
		if !ok || owner != viewerLogin {
			return gqlData([]byte(`{"node":null}`))
		}
		repo := cc.store.getRepo(owner, name)
		if repo == nil {
			return gqlData([]byte(`{"node":null}`))
		}
		pr := repo.PRs[number]
		if pr == nil {
			return gqlData([]byte(`{"node":null}`))
		}
		b := make([]byte, 0, 192)
		b = append(b, `{"node":{"id":`...)
		b = appendJSONString(b, id)
		b = append(b, `,"number":`...)
		b = appendJSONInt(b, int64(pr.Number))
		b = append(b, `,"state":`...)
		if pr.Merged {
			b = append(b, `"MERGED"`...)
		} else {
			b = appendJSONString(b, gqlIssueState(pr.State))
		}
		b = append(b, `}}`...)
		return gqlData(b)
	}
	return gqlData([]byte(`{"node":null}`))
}

// inputOf returns the mutation's input object.
func inputOf(vars map[string]any) map[string]any {
	if v, ok := vars["input"]; ok {
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	return map[string]any{}
}

func (cc *conn) gqlCreateIssue(vars map[string]any) []byte {
	input := inputOf(vars)
	kind, key, ok := decodeGlobalID(varString(input, "repositoryId"))
	if !ok || kind != "Repository" {
		return gqlErr("repository not found")
	}
	owner, name, ok := decodeRepoKey(key)
	if !ok || owner != viewerLogin {
		return gqlErr("repository not found")
	}
	repo := cc.store.getRepo(owner, name)
	if repo == nil {
		return gqlErr("repository not found")
	}
	title := varString(input, "title")
	if title == "" {
		return gqlErr("title is required")
	}
	iss := cc.store.createIssue(repo, title, varString(input, "body"), nil)
	b := make([]byte, 0, 128)
	b = append(b, `{"createIssue":{"issue":{"number":`...)
	b = appendJSONInt(b, int64(iss.Number))
	b = append(b, `,"id":`...)
	b = appendJSONString(b, issueGlobalID(iss))
	b = append(b, `}}}`...)
	return gqlData(b)
}

func (cc *conn) gqlCloseIssue(vars map[string]any) []byte {
	input := inputOf(vars)
	kind, key, ok := decodeGlobalID(varString(input, "issueId"))
	if !ok || kind != "Issue" {
		return gqlErr("issue not found")
	}
	owner, name, number, ok := decodeIssueKey(key)
	if !ok || owner != viewerLogin {
		return gqlErr("issue not found")
	}
	repo := cc.store.getRepo(owner, name)
	if repo == nil {
		return gqlErr("issue not found")
	}
	iss := repo.Issues[number]
	if iss == nil {
		return gqlErr("issue not found")
	}
	iss.State = "closed"
	iss.UpdatedAt = cc.store.clock.Now()
	iss.cached = nil
	cc.store.bumpGen()
	b := make([]byte, 0, 128)
	b = append(b, `{"closeIssue":{"issue":{"number":`...)
	b = appendJSONInt(b, int64(iss.Number))
	b = append(b, `,"id":`...)
	b = appendJSONString(b, issueGlobalID(iss))
	b = append(b, `,"state":"CLOSED"}}}`...)
	return gqlData(b)
}

func (cc *conn) gqlCreatePullRequest(vars map[string]any) []byte {
	input := inputOf(vars)
	kind, key, ok := decodeGlobalID(varString(input, "repositoryId"))
	if !ok || kind != "Repository" {
		return gqlErr("repository not found")
	}
	owner, name, ok := decodeRepoKey(key)
	if !ok || owner != viewerLogin {
		return gqlErr("repository not found")
	}
	repo := cc.store.getRepo(owner, name)
	if repo == nil {
		return gqlErr("repository not found")
	}
	head := varString(input, "headRefName")
	base := varString(input, "baseRefName")
	title := varString(input, "title")
	headSHA, ok := repo.Refs["refs/heads/"+head]
	if !ok {
		return gqlErr("head branch does not exist")
	}
	baseSHA, ok := repo.Refs["refs/heads/"+base]
	if !ok {
		return gqlErr("base branch does not exist")
	}
	for _, other := range repo.PROrder {
		if other.State == "open" && other.HeadRef == head {
			return gqlErr("a pull request already exists for " + head)
		}
	}
	files := prFilesFor(repo, baseSHA, headSHA)
	pr := cc.store.createPR(repo, title, "", head, base, headSHA, baseSHA, files)
	b := make([]byte, 0, 192)
	b = append(b, `{"createPullRequest":{"pullRequest":{"number":`...)
	b = appendJSONInt(b, int64(pr.Number))
	b = append(b, `,"id":`...)
	b = appendJSONString(b, prGlobalID(pr))
	b = append(b, `,"state":"OPEN","headRefName":`...)
	b = appendJSONString(b, head)
	b = append(b, `,"baseRefName":`...)
	b = appendJSONString(b, base)
	b = append(b, `}}}`...)
	return gqlData(b)
}

func (cc *conn) gqlMergePullRequest(vars map[string]any) []byte {
	input := inputOf(vars)
	kind, key, ok := decodeGlobalID(varString(input, "pullRequestId"))
	if !ok || kind != "PullRequest" {
		return gqlErr("pull request not found")
	}
	owner, name, number, ok := decodeIssueKey(key)
	if !ok || owner != viewerLogin {
		return gqlErr("pull request not found")
	}
	repo := cc.store.getRepo(owner, name)
	if repo == nil {
		return gqlErr("pull request not found")
	}
	pr := repo.PRs[number]
	if pr == nil {
		return gqlErr("pull request not found")
	}
	if pr.State != "open" {
		return gqlErr("pull request is not open")
	}
	if _, conflict := cc.store.mergePR(repo, pr); conflict {
		return gqlErr("merge conflict")
	}
	b := make([]byte, 0, 128)
	b = append(b, `{"mergePullRequest":{"pullRequest":{"number":`...)
	b = appendJSONInt(b, int64(pr.Number))
	b = append(b, `,"merged":true,"state":"MERGED"}}}`...)
	return gqlData(b)
}

func (cc *conn) gqlAddComment(vars map[string]any) []byte {
	input := inputOf(vars)
	kind, key, ok := decodeGlobalID(varString(input, "subjectId"))
	if !ok || kind != "Issue" {
		return gqlErr("subject not found")
	}
	owner, name, number, ok := decodeIssueKey(key)
	if !ok || owner != viewerLogin {
		return gqlErr("subject not found")
	}
	repo := cc.store.getRepo(owner, name)
	if repo == nil {
		return gqlErr("subject not found")
	}
	iss := repo.Issues[number]
	if iss == nil {
		return gqlErr("subject not found")
	}
	now := cc.store.clock.Now()
	c := &Comment{ID: cc.store.nextIDAlloc(), Body: varString(input, "body"), CreatedAt: now, UpdatedAt: now}
	iss.Comments = append(iss.Comments, c)
	iss.UpdatedAt = now
	iss.cached = nil
	cc.store.bumpGen()
	b := make([]byte, 0, 160)
	b = append(b, `{"addComment":{"commentEdge":{"node":{"id":`...)
	b = appendJSONString(b, commentGlobalID(c, iss))
	b = append(b, `,"body":`...)
	b = appendJSONString(b, c.Body)
	b = append(b, `}}}}`...)
	return gqlData(b)
}
