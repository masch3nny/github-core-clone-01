// REST v3 handlers: repos, branches, commits, contents, labels, issues,
// pull requests. All handlers run with the store's write lock held (taken
// in restRoute); helpers assume the lock is held.
package main

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

// restRoute dispatches /api/v3/* requests.
func (cc *conn) restRoute() {
	r := &cc.req
	cc.store.mu.Lock()
	defer cc.store.mu.Unlock()

	segs := splitPath(r.path)
	// segs[0] == "api", segs[1] == "v3"
	if len(segs) < 2 {
		cc.notFound("")
		return
	}
	// GET /api/v3/
	if len(segs) == 2 {
		if r.method != "GET" {
			cc.notFound("")
			return
		}
		origin := r.origin()
		body := []byte(`{"current_user_url":` + jsonString(origin+"/api/v3/user") +
			`,"repository_url":` + jsonString(origin+"/api/v3/repos/{owner}/{repo}") +
			`,"rate_limit_url":` + jsonString(origin+"/api/v3/rate_limit") + `}`)
		cc.writeJSON(200, body, "X-OAuth-Scopes", "repo, read:org")
		return
	}
	switch segs[2] {
	case "meta":
		if r.method == "GET" {
			cc.writeJSON(200, []byte(`{"installed_version":"1.0.0"}`))
		} else {
			cc.notFound("")
		}
	case "user":
		cc.restUser(segs)
	case "repos":
		cc.restRepos(segs)
	default:
		cc.notFound("")
	}
}

// splitPath splits "/a/b/c" into ["a","b","c"].
func splitPath(p string) []string {
	if p == "/" {
		return nil
	}
	parts := strings.Split(p, "/")
	// strings.Split("/a/b", "/") gives ["", "a", "b"]; drop the leading "".
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}
	return parts
}

// jsonString renders a string as a JSON string literal (for small literals).
func jsonString(s string) string {
	return string(appendJSONString(nil, s))
}

// parseBody parses the request body as a JSON object. An empty body is {}.
// Returns nil + false when the body is malformed JSON (caller answers 400).
func (cc *conn) parseBody() (map[string]any, bool) {
	if len(cc.req.body) == 0 {
		return map[string]any{}, true
	}
	var m map[string]any
	if err := json.Unmarshal(cc.req.body, &m); err != nil {
		return nil, false
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, true
}

// badJSON answers 400 for a malformed JSON body.
func (cc *conn) badJSON() {
	cc.writeJSON(400, errorJSON("malformed JSON body"))
}

// bodyString reads a string field from a parsed body.
func bodyString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// bodyBool reads a bool field from a parsed body.
func bodyBool(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// lookupRepo resolves owner/name to a repository: any owner other than the
// viewer is 404 (never 403), as is a missing repository.
func (cc *conn) lookupRepo(owner, name string) *Repo {
	if owner != viewerLogin {
		cc.notFound("repository not found")
		return nil
	}
	r := cc.store.getRepo(owner, name)
	if r == nil {
		cc.notFound("repository not found")
		return nil
	}
	return r
}

// ---------------------------------------------------------------- /user

func (cc *conn) restUser(segs []string) {
	r := &cc.req
	if len(segs) == 3 {
		// GET /api/v3/user
		if r.method != "GET" {
			cc.notFound("")
			return
		}
		body := []byte(`{"login":"adaiversen","id":1000,"name":"ada iversen","email":"adaiversen@example.invalid","type":"User"}`)
		cc.writeJSON(200, body)
		return
	}
	if len(segs) == 4 && segs[3] == "repos" {
		switch r.method {
		case "GET":
			cc.listUserRepos()
		case "POST":
			cc.createUserRepo()
		default:
			cc.notFound("")
		}
		return
	}
	cc.notFound("")
}

// listUserRepos answers GET /api/v3/user/repos with Link pagination.
func (cc *conn) listUserRepos() {
	r := &cc.req
	perPage := 30
	if v := r.qval("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			perPage = n
		}
	}
	page := 1
	if v := r.qval("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	repos := cc.store.viewerRepos()
	total := len(repos)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	origin := r.origin()
	b := make([]byte, 0, 256*max(1, end-start))
	b = append(b, '[')
	for i := start; i < end; i++ {
		if i > start {
			b = append(b, ',')
		}
		b = append(b, repoJSON(repos[i], origin)...)
	}
	b = append(b, ']')
	var extra []string
	if end < total {
		next := origin + "/api/v3/user/repos?per_page=" + strconv.Itoa(perPage) + "&page=" + strconv.Itoa(page+1)
		lastPage := (total + perPage - 1) / perPage
		last := origin + "/api/v3/user/repos?per_page=" + strconv.Itoa(perPage) + "&page=" + strconv.Itoa(lastPage)
		extra = []string{"Link", `<` + next + `>; rel="next", <` + last + `>; rel="last"`}
	}
	cc.writeJSON(200, b, extra...)
}

// createUserRepo answers POST /api/v3/user/repos.
func (cc *conn) createUserRepo() {
	m, ok := cc.parseBody()
	if !ok {
		cc.badJSON()
		return
	}
	name := bodyString(m, "name")
	if name == "" {
		cc.writeJSON(422, errorJSON("name is required"))
		return
	}
	if cc.store.getRepo(viewerLogin, name) != nil {
		cc.writeJSON(422, errorJSON("repository already exists"))
		return
	}
	repo := cc.store.createRepo(name, bodyBool(m, "private"), bodyString(m, "description"))
	cc.writeJSON(201, repoJSON(repo, cc.req.origin()))
}

// ---------------------------------------------------------------- /repos/{owner}/{repo}

func (cc *conn) restRepos(segs []string) {
	r := &cc.req
	if len(segs) < 5 {
		cc.notFound("")
		return
	}
	owner, name := segs[3], segs[4]
	repo := cc.lookupRepo(owner, name)
	if repo == nil {
		return
	}
	rest := segs[5:]
	if len(rest) == 0 {
		switch r.method {
		case "GET":
			cc.writeJSON(200, repoJSON(repo, r.origin()))
		case "PATCH":
			m, ok := cc.parseBody()
			if !ok {
				cc.badJSON()
				return
			}
			if v, present := m["description"]; present {
				if s, isStr := v.(string); isStr {
					repo.Description = s
				}
			}
			if _, present := m["private"]; present {
				repo.Private = bodyBool(m, "private")
			}
			repo.UpdatedAt = cc.store.clock.Now()
			repo.cached = nil
			cc.store.bumpGen()
			cc.writeJSON(200, repoJSON(repo, r.origin()))
		case "DELETE":
			cc.store.deleteRepo(repo)
			cc.writeResp(204, "application/json", nil)
		default:
			cc.notFound("")
		}
		return
	}
	switch rest[0] {
	case "branches":
		cc.restBranches(repo, rest[1:])
	case "commits":
		cc.restCommits(repo)
	case "git":
		cc.restGitRefs(repo, rest[1:])
	case "contents":
		cc.restContents(repo, rest[1:])
	case "labels":
		cc.restLabels(repo, rest[1:])
	case "issues":
		cc.restIssues(repo, rest[1:])
	case "pulls":
		cc.restPulls(repo, rest[1:])
	default:
		cc.notFound("")
	}
}

// restBranches handles /branches and /branches/{branch}.
func (cc *conn) restBranches(repo *Repo, rest []string) {
	r := &cc.req
	if r.method != "GET" {
		cc.notFound("")
		return
	}
	if len(rest) == 0 {
		names := repo.refNames()
		b := make([]byte, 0, 256)
		b = append(b, '[')
		first := true
		for _, ref := range names {
			if !strings.HasPrefix(ref, "refs/heads/") {
				continue
			}
			if !first {
				b = append(b, ',')
			}
			first = false
			b = append(b, branchJSON(ref[len("refs/heads/"):], repo.Refs[ref])...)
		}
		b = append(b, ']')
		cc.writeJSON(200, b)
		return
	}
	if len(rest) == 1 {
		oid, ok := repo.Refs["refs/heads/"+rest[0]]
		if !ok {
			cc.notFound("branch not found")
			return
		}
		cc.writeJSON(200, branchJSON(rest[0], oid))
		return
	}
	cc.notFound("")
}

// restCommits handles GET /commits[?sha=<ref>].
func (cc *conn) restCommits(repo *Repo) {
	r := &cc.req
	if r.method != "GET" {
		cc.notFound("")
		return
	}
	ref := r.qval("sha")
	var tip string
	if ref == "" {
		tip = repo.headOID()
	} else if strings.HasPrefix(ref, "refs/heads/") {
		tip = repo.Refs[ref]
	} else if oid, ok := repo.Refs["refs/heads/"+ref]; ok {
		tip = oid
	} else if _, ok := repo.Objects[ref]; ok {
		tip = ref
	}
	if tip == "" {
		cc.writeJSON(200, []byte("[]"))
		return
	}
	commits := reachableCommits(repo, tip)
	b := make([]byte, 0, 256*len(commits))
	b = append(b, '[')
	for i, oid := range commits {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, commitListJSON(oid, repo.Objects[oid])...)
	}
	b = append(b, ']')
	cc.writeJSON(200, b)
}

// restGitRefs handles POST /git/refs and GET /git/refs/heads/{branch}.
func (cc *conn) restGitRefs(repo *Repo, rest []string) {
	r := &cc.req
	if len(rest) >= 1 && rest[0] == "refs" {
		if r.method == "POST" && len(rest) == 1 {
			m, ok := cc.parseBody()
			if !ok {
				cc.badJSON()
				return
			}
			ref := bodyString(m, "ref")
			sha := bodyString(m, "sha")
			if ref == "" || sha == "" {
				cc.writeJSON(422, errorJSON("ref and sha are required"))
				return
			}
			if _, exists := repo.Refs[ref]; exists {
				cc.writeJSON(422, errorJSON("reference already exists"))
				return
			}
			if _, ok := repo.Objects[sha]; !ok {
				cc.writeJSON(422, errorJSON("object does not exist"))
				return
			}
			repo.Refs[ref] = sha
			cc.store.bumpGen()
			b := []byte(`{"ref":` + jsonString(ref) + `,"object":{"sha":` + jsonString(sha) + `,"type":"commit"}}`)
			cc.writeJSON(201, b)
			return
		}
		if r.method == "GET" && len(rest) == 3 && rest[1] == "heads" {
			oid, ok := repo.Refs["refs/heads/"+rest[2]]
			if !ok {
				cc.notFound("reference not found")
				return
			}
			b := []byte(`{"ref":"refs/heads/` + rest[2] + `","object":{"sha":` + jsonString(oid) + `,"type":"commit"}}`)
			cc.writeJSON(200, b)
			return
		}
	}
	cc.notFound("")
}

// ---------------------------------------------------------------- contents

// restContents handles GET/PUT/DELETE /contents/{path...}.
func (cc *conn) restContents(repo *Repo, rest []string) {
	r := &cc.req
	path := strings.Join(rest, "/")
	switch r.method {
	case "GET":
		cc.getContents(repo, path)
	case "PUT":
		cc.putContents(repo, path)
	case "DELETE":
		cc.deleteContents(repo, path)
	default:
		cc.notFound("")
	}
}

// resolveRef resolves a ref query value (branch name, full ref, or commit
// oid) to a commit oid; "" means the default branch tip.
func resolveRef(repo *Repo, ref string) string {
	if ref == "" {
		return repo.headOID()
	}
	if strings.HasPrefix(ref, "refs/") {
		return repo.Refs[ref]
	}
	if oid, ok := repo.Refs["refs/heads/"+ref]; ok {
		return oid
	}
	if obj, ok := repo.Objects[ref]; ok && obj.Type == "commit" {
		return ref
	}
	return ""
}

func (cc *conn) getContents(repo *Repo, path string) {
	r := &cc.req
	tip := resolveRef(repo, r.qval("ref"))
	if tip == "" {
		cc.notFound("not found")
		return
	}
	commit := repo.Objects[tip]
	if commit == nil || commit.Type != "commit" {
		cc.notFound("not found")
		return
	}
	oid, typ, ok := lookupPath(repo, commit.tree, path)
	if !ok {
		cc.notFound("not found")
		return
	}
	if typ == "blob" {
		obj := repo.Objects[oid]
		b := fileJSON(repo, path, oid, obj)
		cc.writeJSON(200, b)
		return
	}
	// Directory listing.
	entries, ok := listDir(repo, commit.tree, path)
	if !ok {
		cc.notFound("not found")
		return
	}
	b := make([]byte, 0, 256)
	b = append(b, '[')
	for i, e := range entries {
		if i > 0 {
			b = append(b, ',')
		}
		etype := "file"
		if e.mode == "40000" {
			etype = "dir"
		}
		b = append(b, `{"type":`...)
		b = appendJSONString(b, etype)
		b = append(b, `,"name":`...)
		b = appendJSONString(b, e.name)
		b = append(b, `,"path":`...)
		full := e.name
		if path != "" {
			full = path + "/" + e.name
		}
		b = appendJSONString(b, full)
		b = append(b, `,"sha":`...)
		b = appendJSONString(b, e.oid)
		b = append(b, `,"size":0}`...)
	}
	b = append(b, ']')
	cc.writeJSON(200, b)
}

// fileJSON renders a contents file object.
func fileJSON(repo *Repo, path, oid string, obj *GitObject) []byte {
	name := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		name = path[i+1:]
	}
	b := make([]byte, 0, len(obj.Data)*2+256)
	b = append(b, `{"type":"file","encoding":"base64","size":`...)
	b = appendJSONInt(b, int64(len(obj.Data)))
	b = append(b, `,"name":`...)
	b = appendJSONString(b, name)
	b = append(b, `,"path":`...)
	b = appendJSONString(b, path)
	b = append(b, `,"content":`...)
	b = appendJSONString(b, base64.StdEncoding.EncodeToString(obj.Data))
	b = append(b, `,"sha":`...)
	b = appendJSONString(b, oid)
	b = append(b, `}`...)
	return b
}

func (cc *conn) putContents(repo *Repo, path string) {
	m, ok := cc.parseBody()
	if !ok {
		cc.badJSON()
		return
	}
	message := bodyString(m, "message")
	contentB64 := bodyString(m, "content")
	data, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		cc.writeJSON(422, errorJSON("content is not valid base64"))
		return
	}
	// Target branch: body.branch, else the default branch. A named branch
	// that does not exist is created from the default tip.
	branch := bodyString(m, "branch")
	if branch == "" {
		branch = repo.DefaultBranch
	}
	refName := "refs/heads/" + branch
	tip, exists := repo.Refs[refName]
	if !exists {
		// Create the branch from the default tip (or unborn when empty).
		tip = repo.headOID()
		repo.Refs[refName] = tip
	}
	var curTree string
	if tip != "" {
		if commit := repo.Objects[tip]; commit != nil {
			curTree = commit.tree
		}
	}
	files := flattenTree(repo, curTree)
	sha := bodyString(m, "sha")
	existing, hasExisting := files[path]
	if sha != "" {
		// Update: the stored blob must match the given sha.
		if !hasExisting || existing != sha {
			cc.writeJSON(409, errorJSON("sha does not match"))
			return
		}
	} else if hasExisting {
		cc.writeJSON(422, errorJSON("file already exists"))
		return
	}
	blob := newGitObject("blob", data)
	repo.Objects[blob.OID] = blob
	files[path] = blob.OID
	newTree := buildTree(repo, files)
	var parents []string
	if tip != "" {
		parents = []string{tip}
	}
	commitOID := cc.store.makeCommit(repo, newTree, parents, message)
	repo.Refs[refName] = commitOID
	cc.store.bumpGen()
	status := 201
	if sha != "" {
		status = 200
	}
	b := make([]byte, 0, 512)
	b = append(b, `{"content":`...)
	b = append(b, fileJSON(repo, path, blob.OID, blob)...)
	b = append(b, `,"commit":{"sha":`...)
	b = appendJSONString(b, commitOID)
	b = append(b, `,"message":`...)
	b = appendJSONString(b, message)
	b = append(b, `}}`...)
	cc.writeJSON(status, b)
}

func (cc *conn) deleteContents(repo *Repo, path string) {
	m, ok := cc.parseBody()
	if !ok {
		cc.badJSON()
		return
	}
	message := bodyString(m, "message")
	branch := bodyString(m, "branch")
	if branch == "" {
		branch = repo.DefaultBranch
	}
	refName := "refs/heads/" + branch
	tip, exists := repo.Refs[refName]
	if !exists || tip == "" {
		cc.notFound("not found")
		return
	}
	commit := repo.Objects[tip]
	if commit == nil {
		cc.notFound("not found")
		return
	}
	files := flattenTree(repo, commit.tree)
	sha := bodyString(m, "sha")
	existing, hasExisting := files[path]
	if !hasExisting || (sha != "" && existing != sha) {
		cc.writeJSON(409, errorJSON("sha does not match"))
		return
	}
	delete(files, path)
	newTree := buildTree(repo, files)
	commitOID := cc.store.makeCommit(repo, newTree, []string{tip}, message)
	repo.Refs[refName] = commitOID
	cc.store.bumpGen()
	b := []byte(`{"commit":{"sha":` + jsonString(commitOID) + `,"message":` + jsonString(message) + `}}`)
	cc.writeJSON(200, b)
}

// ---------------------------------------------------------------- labels

func (cc *conn) restLabels(repo *Repo, rest []string) {
	r := &cc.req
	if len(rest) != 0 {
		cc.notFound("")
		return
	}
	switch r.method {
	case "GET":
		b := make([]byte, 0, 128)
		b = append(b, '[')
		for i, l := range repo.LabelOrder {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, labelJSON(l)...)
		}
		b = append(b, ']')
		cc.writeJSON(200, b)
	case "POST":
		m, ok := cc.parseBody()
		if !ok {
			cc.badJSON()
			return
		}
		name := bodyString(m, "name")
		if name == "" {
			cc.writeJSON(422, errorJSON("name is required"))
			return
		}
		if _, exists := repo.Labels[name]; exists {
			cc.writeJSON(422, errorJSON("label already exists"))
			return
		}
		color := bodyString(m, "color")
		if color == "" {
			color = "000000"
		}
		l := &Label{Name: name, Color: color}
		repo.Labels[name] = l
		repo.LabelOrder = append(repo.LabelOrder, l)
		cc.store.bumpGen()
		cc.writeJSON(201, labelJSON(l))
	default:
		cc.notFound("")
	}
}

// ---------------------------------------------------------------- issues

func (cc *conn) restIssues(repo *Repo, rest []string) {
	r := &cc.req
	if len(rest) == 0 {
		switch r.method {
		case "GET":
			cc.listIssues(repo)
		case "POST":
			cc.createIssue(repo)
		default:
			cc.notFound("")
		}
		return
	}
	num, err := strconv.Atoi(rest[0])
	if err != nil || num <= 0 {
		cc.notFound("")
		return
	}
	iss := repo.Issues[num]
	if iss == nil {
		cc.notFound("issue not found")
		return
	}
	if len(rest) == 1 {
		switch r.method {
		case "GET":
			cc.writeJSON(200, issueJSON(iss))
		case "PATCH":
			m, ok := cc.parseBody()
			if !ok {
				cc.badJSON()
				return
			}
			if v, present := m["state"]; present {
				if s, isStr := v.(string); isStr && (s == "open" || s == "closed") {
					iss.State = s
				}
			}
			if v, present := m["title"]; present {
				if s, isStr := v.(string); isStr {
					iss.Title = s
				}
			}
			if v, present := m["body"]; present {
				if s, isStr := v.(string); isStr {
					iss.Body = s
				}
			}
			iss.UpdatedAt = cc.store.clock.Now()
			iss.cached = nil
			cc.store.bumpGen()
			cc.writeJSON(200, issueJSON(iss))
		default:
			cc.notFound("")
		}
		return
	}
	if len(rest) == 2 && rest[1] == "comments" {
		switch r.method {
		case "GET":
			b := make([]byte, 0, 256)
			b = append(b, '[')
			for i, c := range iss.Comments {
				if i > 0 {
					b = append(b, ',')
				}
				b = append(b, commentJSON(c)...)
			}
			b = append(b, ']')
			cc.writeJSON(200, b)
		case "POST":
			m, ok := cc.parseBody()
			if !ok {
				cc.badJSON()
				return
			}
			now := cc.store.clock.Now()
			c := &Comment{ID: cc.store.nextIDAlloc(), Body: bodyString(m, "body"), CreatedAt: now, UpdatedAt: now}
			iss.Comments = append(iss.Comments, c)
			iss.UpdatedAt = now
			iss.cached = nil
			cc.store.bumpGen()
			cc.writeJSON(201, commentJSON(c))
		default:
			cc.notFound("")
		}
		return
	}
	cc.notFound("")
}

func (cc *conn) listIssues(repo *Repo) {
	r := &cc.req
	state := r.qval("state")
	if state == "" {
		state = "open"
	}
	direction := r.qval("direction")
	if direction == "" {
		direction = "desc"
	}
	// Filter by state, then order by creation (asc = creation order).
	var list []*Issue
	for _, iss := range repo.IssueOrder {
		if state == "all" || iss.State == state {
			list = append(list, iss)
		}
	}
	if direction == "desc" {
		for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
			list[i], list[j] = list[j], list[i]
		}
	}
	b := make([]byte, 0, 256*len(list))
	b = append(b, '[')
	for i, iss := range list {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, issueJSON(iss)...)
	}
	b = append(b, ']')
	cc.writeJSON(200, b)
}

func (cc *conn) createIssue(repo *Repo) {
	m, ok := cc.parseBody()
	if !ok {
		cc.badJSON()
		return
	}
	title := bodyString(m, "title")
	if title == "" {
		cc.writeJSON(422, errorJSON("title is required"))
		return
	}
	var labels []*Label
	if raw, present := m["labels"]; present {
		if arr, isArr := raw.([]any); isArr {
			for _, item := range arr {
				name := ""
				switch v := item.(type) {
				case string:
					name = v
				case map[string]any:
					name = bodyString(v, "name")
				}
				if name == "" {
					continue
				}
				l, exists := repo.Labels[name]
				if !exists {
					cc.writeJSON(422, errorJSON("label does not exist: "+name))
					return
				}
				labels = append(labels, l)
			}
		}
	}
	iss := cc.store.createIssue(repo, title, bodyString(m, "body"), labels)
	cc.writeJSON(201, issueJSON(iss))
}

// ---------------------------------------------------------------- pulls

func (cc *conn) restPulls(repo *Repo, rest []string) {
	r := &cc.req
	if len(rest) == 0 {
		switch r.method {
		case "GET":
			cc.listPulls(repo)
		case "POST":
			cc.createPull(repo)
		default:
			cc.notFound("")
		}
		return
	}
	num, err := strconv.Atoi(rest[0])
	if err != nil || num <= 0 {
		cc.notFound("")
		return
	}
	pr := repo.PRs[num]
	if pr == nil {
		cc.notFound("pull request not found")
		return
	}
	if len(rest) == 1 {
		if r.method == "GET" {
			cc.writeJSON(200, prJSON(pr))
			return
		}
		cc.notFound("")
		return
	}
	if len(rest) == 2 && rest[1] == "files" && r.method == "GET" {
		b := make([]byte, 0, 256)
		b = append(b, '[')
		for i, f := range pr.Files {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, `{"filename":`...)
			b = appendJSONString(b, f.Path)
			b = append(b, `,"status":`...)
			b = appendJSONString(b, f.Status)
			b = append(b, `,"additions":`...)
			b = appendJSONInt(b, int64(f.Additions))
			b = append(b, `,"deletions":`...)
			b = appendJSONInt(b, int64(f.Deletions))
			b = append(b, `,"changes":`...)
			b = appendJSONInt(b, int64(f.Additions+f.Deletions))
			b = append(b, `}`...)
		}
		b = append(b, ']')
		cc.writeJSON(200, b)
		return
	}
	if len(rest) == 2 && rest[1] == "merge" && r.method == "PUT" {
		cc.mergePull(repo, pr)
		return
	}
	cc.notFound("")
}

func (cc *conn) listPulls(repo *Repo) {
	r := &cc.req
	state := r.qval("state")
	if state == "" {
		state = "open"
	}
	b := make([]byte, 0, 256)
	b = append(b, '[')
	first := true
	for _, pr := range repo.PROrder {
		if state != "all" && pr.State != state {
			continue
		}
		if !first {
			b = append(b, ',')
		}
		first = false
		b = append(b, prJSON(pr)...)
	}
	b = append(b, ']')
	cc.writeJSON(200, b)
}

func (cc *conn) createPull(repo *Repo) {
	m, ok := cc.parseBody()
	if !ok {
		cc.badJSON()
		return
	}
	title := bodyString(m, "title")
	head := bodyString(m, "head")
	base := bodyString(m, "base")
	if title == "" || head == "" || base == "" {
		cc.writeJSON(422, errorJSON("title, head and base are required"))
		return
	}
	headSHA, ok := repo.Refs["refs/heads/"+head]
	if !ok {
		cc.writeJSON(422, errorJSON("head branch does not exist"))
		return
	}
	baseSHA, ok := repo.Refs["refs/heads/"+base]
	if !ok {
		cc.writeJSON(422, errorJSON("base branch does not exist"))
		return
	}
	// A second open PR from the same head branch is rejected.
	for _, other := range repo.PROrder {
		if other.State == "open" && other.HeadRef == head {
			cc.writeJSON(422, errorJSON("a pull request already exists for "+head))
			return
		}
	}
	files := prFilesFor(repo, baseSHA, headSHA)
	pr := cc.store.createPR(repo, title, bodyString(m, "body"), head, base, headSHA, baseSHA, files)
	cc.writeJSON(201, prJSON(pr))
}

// mergePull squash-merges a pull request.
func (cc *conn) mergePull(repo *Repo, pr *PR) {
	if pr.State != "open" {
		cc.writeJSON(405, errorJSON("pull request is not open"))
		return
	}
	mergeSHA, conflict := cc.store.mergePR(repo, pr)
	if conflict {
		cc.writeJSON(405, errorJSON("merge conflict"))
		return
	}
	b := []byte(`{"sha":` + jsonString(mergeSHA) + `,"merged":true,"message":` + jsonString("merged pull request #"+strconv.Itoa(pr.Number)) + `}`)
	cc.writeJSON(200, b)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
