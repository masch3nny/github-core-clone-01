// Store: the in-memory deterministic state of the forge.
//
// Every stored object is created from counters and a fixed trial-now base
// plus a strictly increasing millisecond counter; no wall clock, no random
// ids ever enter stored state, so a replay leaves the same state export.
package main

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

// The frozen scenario constants (the suite's scenario seed is constant, so
// the viewer identity is a spec constant, like the benchmark T_refs).
const (
	viewerLogin = "adaiversen"
	viewerID    = 1000
	viewerName  = "ada iversen"
	viewerEmail = "adaiversen@example.invalid"
)

// zeroOID is git's all-zero object id.
const zeroOID = "0000000000000000000000000000000000000000"

// Clock is a deterministic clock: a fixed base (the trial's now) plus a
// strictly increasing millisecond counter.
type Clock struct {
	mu   sync.Mutex
	base int64
	next int64
}

func newClock(baseMs int64) *Clock { return &Clock{base: baseMs} }

// Now returns the next deterministic millisecond timestamp.
func (c *Clock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	return c.base + c.next
}

// ---------------------------------------------------------------- git objects

// GitObject is one stored git object: type + raw bytes (without the
// "<type> <size>\0" header). OID is the hex SHA-1 of header+bytes.
type GitObject struct {
	Type    string // "commit" | "tree" | "blob" | "tag"
	Data    []byte
	OID     string
	parents []string // parsed for commits (nil otherwise)
	tree    string   // parsed tree oid for commits
}

// gitOID computes the SHA-1 object id of type+data.
func gitOID(typ string, data []byte) string {
	h := sha1.New()
	h.Write([]byte(typ))
	h.Write([]byte(" "))
	h.Write([]byte(strconv.Itoa(len(data))))
	h.Write([]byte{0})
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// newGitObject builds an object and its id.
func newGitObject(typ string, data []byte) *GitObject {
	o := &GitObject{Type: typ, Data: data, OID: gitOID(typ, data)}
	if typ == "commit" {
		o.parents, o.tree = parseCommitHeader(data)
	}
	return o
}

// parseCommitHeader extracts parent oids and the tree oid from commit bytes.
func parseCommitHeader(data []byte) (parents []string, tree string) {
	// Headers run until the first blank line; each is "<key> <value>\n".
	i := 0
	for i < len(data) {
		j := i
		for j < len(data) && data[j] != '\n' {
			j++
		}
		if j == i { // blank line: end of headers
			break
		}
		line := string(data[i:j])
		if len(line) > 5 && line[:5] == "tree " {
			tree = line[5:]
		} else if len(line) > 7 && line[:7] == "parent " {
			parents = append(parents, line[7:])
		}
		i = j + 1
	}
	return parents, tree
}

// commitTimestamp extracts the committer timestamp (seconds) from commit
// bytes; 0 when absent.
func commitTimestamp(data []byte) int64 {
	i := 0
	for i < len(data) {
		j := i
		for j < len(data) && data[j] != '\n' {
			j++
		}
		if j == i {
			break
		}
		line := string(data[i:j])
		if len(line) > 10 && line[:10] == "committer " {
			// "... <name> <email> <ts> +0000"
			rest := line[10:]
			// timestamp is the last two space-separated fields' first part.
			for k := len(rest) - 1; k >= 0; k-- {
				if rest[k] == ' ' {
					ts, _ := strconv.ParseInt(rest[k+1:], 10, 64)
					// the field after the timestamp is the zone; the
					// timestamp itself is the field before the last space.
					_ = ts
					break
				}
			}
			// Simpler: split on spaces, timestamp is second-to-last field.
			fields := splitSpaces(rest)
			if len(fields) >= 2 {
				if ts, err := strconv.ParseInt(fields[len(fields)-2], 10, 64); err == nil {
					return ts
				}
			}
			return 0
		}
		i = j + 1
	}
	return 0
}

// splitSpaces splits on single spaces (no empty fields for our inputs).
func splitSpaces(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// commitMessage extracts the message (after the blank line) from commit bytes.
func commitMessage(data []byte) string {
	for i := 0; i+1 < len(data); i++ {
		if data[i] == '\n' && data[i+1] == '\n' {
			return string(data[i+2:])
		}
	}
	return ""
}

// commitIdentity extracts the "name <email>" author/committer line value.
func commitIdentity(data []byte, key string) (name, email string, ts int64) {
	i := 0
	for i < len(data) {
		j := i
		for j < len(data) && data[j] != '\n' {
			j++
		}
		if j == i {
			break
		}
		line := string(data[i:j])
		if len(line) > len(key)+1 && line[:len(key)] == key && line[len(key)] == ' ' {
			rest := line[len(key)+1:]
			// "Name <email> ts +0000"
			lt := -1
			gt := -1
			for k := 0; k < len(rest); k++ {
				if rest[k] == '<' {
					lt = k
				}
				if rest[k] == '>' {
					gt = k
				}
			}
			if lt >= 0 && gt > lt {
				name = rest[:lt]
				// trim trailing space
				for len(name) > 0 && name[len(name)-1] == ' ' {
					name = name[:len(name)-1]
				}
				email = rest[lt+1 : gt]
				fields := splitSpaces(rest[gt+1:])
				if len(fields) >= 1 {
					ts, _ = strconv.ParseInt(fields[0], 10, 64)
				}
			}
			return name, email, ts
		}
		i = j + 1
	}
	return "", "", 0
}

// ---------------------------------------------------------------- REST objects

// Label is a repository label.
type Label struct {
	Name  string
	Color string
}

// Comment is an issue comment.
type Comment struct {
	ID        int64
	Body      string
	CreatedAt int64
	UpdatedAt int64
}

// Issue is a repository issue.
type Issue struct {
	ID        int64
	Number    int
	Repo      *Repo
	Title     string
	Body      string
	State     string // "open" | "closed"
	Labels    []*Label
	CreatedAt int64
	UpdatedAt int64
	Comments  []*Comment
	cached    []byte // rendered REST JSON, invalidated on mutation
}

// PRFile is one changed file of a pull request.
type PRFile struct {
	Path      string
	Status    string // "added" | "modified" | "removed"
	Additions int
	Deletions int
}

// PR is a pull request.
type PR struct {
	ID             int64
	Number         int
	Repo           *Repo
	Title          string
	Body           string
	State          string // "open" | "closed"
	Merged         bool
	MergedAt       int64
	MergeCommitSHA string
	HeadRef        string
	BaseRef        string
	HeadSHA        string
	BaseSHA        string
	CreatedAt      int64
	UpdatedAt      int64
	Files          []PRFile
	cached         []byte // rendered REST JSON, invalidated on mutation
}

// Repo is a repository: REST state plus git state.
type Repo struct {
	ID            int64
	Owner         string
	Name          string
	Private       bool
	DefaultBranch string
	Description   string
	CreatedAt     int64
	UpdatedAt     int64

	// git state
	Objects map[string]*GitObject // oid -> object
	Refs    map[string]string     // refname -> oid

	// REST state
	Labels      map[string]*Label
	LabelOrder  []*Label
	Issues      map[int]*Issue
	IssueOrder  []*Issue
	NextIssue   int
	PRs         map[int]*PR
	PROrder     []*PR
	NextPR      int
	cached      []byte // rendered REST JSON, invalidated on mutation
}

// key returns the map key for a repository.
func repoKey(owner, name string) string { return owner + "/" + name }

// refNames returns the ref names sorted (Go map order is random).
func (r *Repo) refNames() []string {
	names := make([]string, 0, len(r.Refs))
	for name := range r.Refs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// headOID returns the oid of the default branch tip, or "" when unborn.
func (r *Repo) headOID() string {
	if r.DefaultBranch == "" {
		return ""
	}
	return r.Refs["refs/heads/"+r.DefaultBranch]
}

// ---------------------------------------------------------------- the store

// cacheEntry is one cached response body, valid while its generation holds.
type cacheEntry struct {
	gen  uint64
	body []byte
}

// Store holds every repository plus the global counters and caches.
type Store struct {
	mu sync.RWMutex

	token string // the bearer token the suite presents

	repos     map[string]*Repo
	repoOrder []*Repo
	nextID    int64 // repo database ids + issue/comment/pr ids share one counter

	clock *Clock
	gen   atomic.Uint64 // global generation, bumped on any mutation

	reqID atomic.Uint64 // X-GitHub-Request-Id counter

	// response caches (validated by generation; cleared when they grow)
	fetchMu  sync.RWMutex
	fetchC   map[string]*cacheEntry
	advertC  map[string]*cacheEntry
	lsrefsC  map[string]*cacheEntry
	toolsList []byte // byte-identical MCP tools/list answer, built once
}

func newStore(token string, trialNowMs int64) *Store {
	s := &Store{
		token:   token,
		repos:   make(map[string]*Repo),
		fetchC:  make(map[string]*cacheEntry),
		advertC: make(map[string]*cacheEntry),
		lsrefsC: make(map[string]*cacheEntry),
		clock:   newClock(trialNowMs),
	}
	s.toolsList = buildToolsList()
	return s
}

// nextIDAlloc allocates the next deterministic global id.
func (s *Store) nextIDAlloc() int64 {
	s.nextID++
	return s.nextID
}

// bumpGen bumps the global generation (call with the write lock held).
// Cache entries carry the generation they were built at, so a lookup after
// a mutation simply misses; no explicit clearing is needed.
func (s *Store) bumpGen() {
	s.gen.Add(1)
}

// getRepo returns the repository, or nil. Call with at least a read lock.
func (s *Store) getRepo(owner, name string) *Repo {
	return s.repos[repoKey(owner, name)]
}

// createRepo creates a repository under the viewer. Returns nil when a repo
// of that name already exists under the viewer.
func (s *Store) createRepo(name string, private bool, description string) *Repo {
	if s.repos[repoKey(viewerLogin, name)] != nil {
		return nil
	}
	now := s.clock.Now()
	r := &Repo{
		ID:            s.nextIDAlloc(),
		Owner:         viewerLogin,
		Name:          name,
		Private:       private,
		DefaultBranch: "main",
		Description:   description,
		CreatedAt:     now,
		UpdatedAt:     now,
		Objects:       make(map[string]*GitObject),
		Refs:          make(map[string]string),
		Labels:        make(map[string]*Label),
		Issues:        make(map[int]*Issue),
		NextIssue:     1,
		PRs:           make(map[int]*PR),
		NextPR:        1,
	}
	s.repos[repoKey(viewerLogin, name)] = r
	s.repoOrder = append(s.repoOrder, r)
	s.bumpGen()
	return r
}

// deleteRepo removes a repository entirely.
func (s *Store) deleteRepo(r *Repo) {
	delete(s.repos, repoKey(r.Owner, r.Name))
	for i, other := range s.repoOrder {
		if other == r {
			s.repoOrder = append(s.repoOrder[:i], s.repoOrder[i+1:]...)
			break
		}
	}
	s.bumpGen()
}

// viewerRepos returns the viewer's repositories in creation order.
func (s *Store) viewerRepos() []*Repo {
	out := make([]*Repo, 0, len(s.repoOrder))
	for _, r := range s.repoOrder {
		if r.Owner == viewerLogin {
			out = append(out, r)
		}
	}
	return out
}

// createIssue creates an issue on a repository.
func (s *Store) createIssue(r *Repo, title, body string, labels []*Label) *Issue {
	now := s.clock.Now()
	iss := &Issue{
		ID:        s.nextIDAlloc(),
		Number:    r.NextIssue,
		Repo:      r,
		Title:     title,
		Body:      body,
		State:     "open",
		Labels:    labels,
		CreatedAt: now,
		UpdatedAt: now,
	}
	r.NextIssue++
	r.Issues[iss.Number] = iss
	r.IssueOrder = append(r.IssueOrder, iss)
	s.bumpGen()
	return iss
}

// createPR creates a pull request on a repository.
func (s *Store) createPR(r *Repo, title, body, headRef, baseRef, headSHA, baseSHA string, files []PRFile) *PR {
	now := s.clock.Now()
	pr := &PR{
		ID:        s.nextIDAlloc(),
		Number:    r.NextPR,
		Repo:      r,
		Title:     title,
		Body:      body,
		State:     "open",
		HeadRef:   headRef,
		BaseRef:   baseRef,
		HeadSHA:   headSHA,
		BaseSHA:   baseSHA,
		CreatedAt: now,
		UpdatedAt: now,
		Files:     files,
	}
	r.NextPR++
	r.PRs[pr.Number] = pr
	r.PROrder = append(r.PROrder, pr)
	s.bumpGen()
	return pr
}
