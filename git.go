// Git smart HTTP: object model helpers, pack framing, upload-pack v2
// (ls-refs + fetch), receive-pack v0 with report-status. All git handlers
// manage their own locking: fetch/advert caches under fetchMu, then the
// store read lock; receive-pack under the store write lock.
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/adler32"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- trees

// treeEntry is one entry of a tree object.
type treeEntry struct {
	mode string // "100644" or "40000"
	name string
	oid  string // hex
}

// parseTree parses tree object bytes into entries.
func parseTree(data []byte) []treeEntry {
	var out []treeEntry
	i := 0
	for i < len(data) {
		// "<mode> <name>\0" + 20-byte oid
		sp := bytes.IndexByte(data[i:], ' ')
		if sp < 0 {
			break
		}
		mode := string(data[i : i+sp])
		nul := bytes.IndexByte(data[i+sp+1:], 0)
		if nul < 0 || i+sp+1+nul+20 > len(data) {
			break
		}
		name := string(data[i+sp+1 : i+sp+1+nul])
		oid := hex.EncodeToString(data[i+sp+1+nul+1 : i+sp+1+nul+21])
		out = append(out, treeEntry{mode: mode, name: name, oid: oid})
		i = i + sp + 1 + nul + 21
	}
	return out
}

// treeOf returns the tree oid of a commit, or "".
func treeOf(repo *Repo, commitOID string) string {
	if obj := repo.Objects[commitOID]; obj != nil && obj.Type == "commit" {
		return obj.tree
	}
	return ""
}

// lookupPath walks a tree to a path; returns the oid and "blob"/"tree".
func lookupPath(repo *Repo, treeOID, path string) (oid, typ string, ok bool) {
	if path == "" {
		return treeOID, "tree", treeOID != ""
	}
	segs := strings.Split(path, "/")
	cur := treeOID
	for i, seg := range segs {
		obj := repo.Objects[cur]
		if obj == nil || obj.Type != "tree" {
			return "", "", false
		}
		found := false
		for _, e := range parseTree(obj.Data) {
			if e.name == seg {
				cur = e.oid
				if i == len(segs)-1 {
					if e.mode == "40000" {
						return e.oid, "tree", true
					}
					return e.oid, "blob", true
				}
				if e.mode != "40000" {
					return "", "", false
				}
				found = true
				break
			}
		}
		if !found {
			return "", "", false
		}
	}
	return cur, "tree", true
}

// listDir returns the entries of the directory at dirPath ("": the root).
func listDir(repo *Repo, treeOID, dirPath string) ([]treeEntry, bool) {
	oid := treeOID
	if dirPath != "" {
		var typ string
		var ok bool
		oid, typ, ok = lookupPath(repo, treeOID, dirPath)
		if !ok || typ != "tree" {
			return nil, false
		}
	}
	obj := repo.Objects[oid]
	if obj == nil || obj.Type != "tree" {
		return nil, false
	}
	return parseTree(obj.Data), true
}

// flattenTree returns path -> blob oid for every file under a tree.
func flattenTree(repo *Repo, treeOID string) map[string]string {
	out := make(map[string]string)
	if treeOID == "" {
		return out
	}
	var walk func(oid, prefix string)
	walk = func(oid, prefix string) {
		obj := repo.Objects[oid]
		if obj == nil || obj.Type != "tree" {
			return
		}
		for _, e := range parseTree(obj.Data) {
			if e.mode == "40000" {
				walk(e.oid, prefix+e.name+"/")
			} else {
				out[prefix+e.name] = e.oid
			}
		}
	}
	walk(treeOID, "")
	return out
}

// buildTree builds tree objects for a path -> blob oid map and returns the
// root tree oid. Objects are stored in the repository.
func buildTree(repo *Repo, files map[string]string) string {
	return buildTreeLevel(repo, files, "")
}

func buildTreeLevel(repo *Repo, files map[string]string, prefix string) string {
	type child struct {
		name, oid, mode string
	}
	var entries []child
	subdirs := map[string]bool{}
	for path, oid := range files {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := path[len(prefix):]
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			subdirs[rest[:i]] = true
		} else {
			entries = append(entries, child{rest, oid, "100644"})
		}
	}
	for dir := range subdirs {
		sub := buildTreeLevel(repo, files, prefix+dir+"/")
		entries = append(entries, child{dir, sub, "40000"})
	}
	// Git tree sort: byte order of the name, a directory compared as if it
	// ended in '/'.
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].name, entries[j].name
		if entries[i].mode == "40000" {
			a += "/"
		}
		if entries[j].mode == "40000" {
			b += "/"
		}
		return a < b
	})
	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteString(e.mode)
		buf.WriteByte(' ')
		buf.WriteString(e.name)
		buf.WriteByte(0)
		raw, _ := hex.DecodeString(e.oid)
		buf.Write(raw)
	}
	obj := newGitObject("tree", buf.Bytes())
	repo.Objects[obj.OID] = obj
	return obj.OID
}

// makeCommit creates a commit object (viewer identity, deterministic
// timestamp) and returns its oid.
func (s *Store) makeCommit(repo *Repo, treeOID string, parents []string, message string) string {
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	ts := s.clock.Now() / 1000
	who := viewerLogin + " <" + viewerEmail + "> " + strconv.FormatInt(ts, 10) + " +0000"
	var b strings.Builder
	b.WriteString("tree " + treeOID + "\n")
	for _, p := range parents {
		b.WriteString("parent " + p + "\n")
	}
	b.WriteString("author " + who + "\n")
	b.WriteString("committer " + who + "\n")
	b.WriteString("\n")
	b.WriteString(message)
	obj := newGitObject("commit", []byte(b.String()))
	repo.Objects[obj.OID] = obj
	return obj.OID
}

// ---------------------------------------------------------------- reachability

// reachableCommits returns the commits reachable from tip, newest first
// (BFS following parents, deduplicated).
func reachableCommits(repo *Repo, tip string) []string {
	var out []string
	seen := map[string]bool{}
	queue := []string{tip}
	for len(queue) > 0 {
		oid := queue[0]
		queue = queue[1:]
		if seen[oid] {
			continue
		}
		seen[oid] = true
		obj := repo.Objects[oid]
		if obj == nil || obj.Type != "commit" {
			continue
		}
		out = append(out, oid)
		queue = append(queue, obj.parents...)
	}
	return out
}

// isAncestor reports whether anc is reachable from desc (anc == desc counts).
func isAncestor(repo *Repo, anc, desc string) bool {
	if anc == desc {
		return true
	}
	for _, oid := range reachableCommits(repo, desc) {
		if oid == anc {
			return true
		}
	}
	return false
}

// mergeBase returns the first common ancestor of a and b (BFS from a, then
// BFS from b); "" when there is none.
func mergeBase(repo *Repo, a, b string) string {
	ancestors := map[string]bool{}
	for _, oid := range reachableCommits(repo, a) {
		ancestors[oid] = true
	}
	for _, oid := range reachableCommits(repo, b) {
		if ancestors[oid] {
			return oid
		}
	}
	return ""
}

// addTreeObjects adds a tree and everything under it to out.
func addTreeObjects(repo *Repo, treeOID string, out map[string]bool) {
	stack := []string{treeOID}
	for len(stack) > 0 {
		oid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if out[oid] {
			continue
		}
		obj := repo.Objects[oid]
		if obj == nil || obj.Type != "tree" {
			continue
		}
		out[oid] = true
		for _, e := range parseTree(obj.Data) {
			if e.mode == "40000" {
				stack = append(stack, e.oid)
			} else {
				out[e.oid] = true
			}
		}
	}
}

// parseTagTarget extracts the "object <oid>" line of a tag object.
func parseTagTarget(data []byte) string {
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
		if len(line) > 7 && line[:7] == "object " {
			return line[7:]
		}
		i = j + 1
	}
	return ""
}

// collectReachable returns the object oids reachable from roots.
// depth <= 0 means unlimited; with depth d, commits at distance <= d-1
// from a root are included. Traversal stops at (does not descend past)
// commits in stopAt, which are themselves included with their trees.
// The returned distances map holds commit distances (for shallow-info).
func collectReachable(repo *Repo, roots []string, depth int, stopAt map[string]bool) (map[string]bool, map[string]int) {
	out := map[string]bool{}
	dist := map[string]int{}
	type item struct {
		oid string
		d   int
	}
	queue := []item{}
	for _, r := range roots {
		queue = append(queue, item{r, 0})
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		oid := it.oid
		if out[oid] {
			continue
		}
		obj := repo.Objects[oid]
		if obj == nil {
			continue
		}
		out[oid] = true
		switch obj.Type {
		case "commit":
			dist[oid] = it.d
			if obj.tree != "" {
				addTreeObjects(repo, obj.tree, out)
			}
			if stopAt[oid] {
				continue
			}
			if depth > 0 && it.d >= depth-1 {
				continue
			}
			for _, p := range obj.parents {
				queue = append(queue, item{p, it.d + 1})
			}
		case "tag":
			if target := parseTagTarget(obj.Data); target != "" {
				queue = append(queue, item{target, it.d})
			}
		case "tree":
			addTreeObjects(repo, oid, out)
		}
	}
	return out, dist
}

// ---------------------------------------------------------------- pkt-lines

const hexdigits = "0123456789abcdef"

func appendPktLen(dst []byte, n int) []byte {
	return append(dst, hexdigits[(n>>12)&0xf], hexdigits[(n>>8)&0xf], hexdigits[(n>>4)&0xf], hexdigits[n&0xf])
}

// pktLine appends one pkt-line (4 hex length bytes + payload).
func pktLine(dst, payload []byte) []byte {
	dst = appendPktLen(dst, len(payload)+4)
	return append(dst, payload...)
}

func pktFlush(dst []byte) []byte { return append(dst, "0000"...) }
func pktDelim(dst []byte) []byte { return append(dst, "0001"...) }

// parsePktLines splits a body into pkt-line payloads. A flush becomes a nil
// entry, a delim becomes an empty-but-non-nil marker: the caller sees them
// via the parallel kinds slice ("line", "flush", "delim").
func parsePktLines(body []byte) ([][]byte, []string, error) {
	var payloads [][]byte
	var kinds []string
	i := 0
	for i < len(body) {
		if len(body)-i < 4 {
			return nil, nil, errors.New("truncated pkt-line")
		}
		n := 0
		for k := 0; k < 4; k++ {
			c := body[i+k]
			var v int
			switch {
			case c >= '0' && c <= '9':
				v = int(c - '0')
			case c >= 'a' && c <= 'f':
				v = int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v = int(c-'A') + 10
			default:
				return nil, nil, errors.New("bad pkt-line length")
			}
			n = n*16 + v
		}
		if n == 0 {
			payloads = append(payloads, nil)
			kinds = append(kinds, "flush")
			i += 4
			continue
		}
		if n == 1 {
			payloads = append(payloads, nil)
			kinds = append(kinds, "delim")
			i += 4
			continue
		}
		if n < 4 || i+n > len(body) {
			return nil, nil, errors.New("bad pkt-line length")
		}
		payloads = append(payloads, body[i+4:i+n])
		kinds = append(kinds, "line")
		i += n
	}
	return payloads, kinds, nil
}

// ---------------------------------------------------------------- packs

// appendZlibStored appends a zlib stream holding data with STORED (level-0)
// deflate blocks: no compression search, deterministic bytes.
func appendZlibStored(dst, data []byte) []byte {
	dst = append(dst, 0x78, 0x01)
	rest := data
	for {
		if len(rest) <= 65535 {
			dst = append(dst, 0x01) // BFINAL=1, BTYPE=00
			dst = append(dst, byte(len(rest)), byte(len(rest)>>8))
			nlen := ^uint16(len(rest))
			dst = append(dst, byte(nlen), byte(nlen>>8))
			dst = append(dst, rest...)
			break
		}
		dst = append(dst, 0x00) // BFINAL=0, BTYPE=00
		dst = append(dst, 0xff, 0xff, 0x00, 0x00)
		dst = append(dst, rest[:65535]...)
		rest = rest[65535:]
	}
	sum := adler32.Checksum(data)
	dst = append(dst, byte(sum>>24), byte(sum>>16), byte(sum>>8), byte(sum))
	return dst
}

func packObjectTypeCode(typ string) int {
	switch typ {
	case "commit":
		return 1
	case "tree":
		return 2
	case "blob":
		return 3
	case "tag":
		return 4
	}
	return 0
}

// appendPackObject appends one object (varint type/size header + stored
// zlib stream) to a pack under construction.
func appendPackObject(dst []byte, o *GitObject) []byte {
	typ := packObjectTypeCode(o.Type)
	size := len(o.Data)
	first := byte(typ<<4) | byte(size&0x0f)
	size >>= 4
	if size > 0 {
		first |= 0x80
	}
	dst = append(dst, first)
	for size > 0 {
		b := byte(size & 0x7f)
		size >>= 7
		if size > 0 {
			b |= 0x80
		}
		dst = append(dst, b)
	}
	return appendZlibStored(dst, o.Data)
}

// writePack appends a complete pack (header, objects sorted by oid, SHA-1
// trailer) for the given objects.
func writePack(dst []byte, objs []*GitObject) []byte {
	start := len(dst)
	dst = append(dst, "PACK"...)
	dst = append(dst, 0, 0, 0, 2)
	n := len(objs)
	dst = append(dst, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	for _, o := range objs {
		dst = appendPackObject(dst, o)
	}
	sum := sha1.Sum(dst[start:])
	return append(dst, sum[:]...)
}

// readPack parses a pack, verifies its trailer checksum, inflates every
// object and verifies each object's size. Delta objects are rejected.
func readPack(data []byte) ([]*GitObject, error) {
	if len(data) < 32 || string(data[:4]) != "PACK" {
		return nil, errors.New("bad pack header")
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version != 2 && version != 3 {
		return nil, errors.New("unsupported pack version")
	}
	count := int(binary.BigEndian.Uint32(data[8:12]))
	sum := sha1.Sum(data[:len(data)-20])
	if !bytes.Equal(sum[:], data[len(data)-20:]) {
		return nil, errors.New("pack checksum mismatch")
	}
	br := bytes.NewReader(data[12 : len(data)-20])
	objs := make([]*GitObject, 0, count)
	for i := 0; i < count; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		typ := (b >> 4) & 7
		size := int(b & 0x0f)
		shift := 4
		for b&0x80 != 0 {
			b, err = br.ReadByte()
			if err != nil {
				return nil, err
			}
			size |= int(b&0x7f) << shift
			shift += 7
		}
		if typ == 6 || typ == 7 {
			return nil, errors.New("delta objects not supported")
		}
		var typeName string
		switch typ {
		case 1:
			typeName = "commit"
		case 2:
			typeName = "tree"
		case 3:
			typeName = "blob"
		case 4:
			typeName = "tag"
		default:
			return nil, errors.New("unknown object type")
		}
		zr, err := zlib.NewReader(br)
		if err != nil {
			return nil, err
		}
		content := make([]byte, size)
		if _, err := io.ReadFull(zr, content); err != nil {
			zr.Close()
			return nil, err
		}
		zr.Close()
		objs = append(objs, newGitObject(typeName, content))
	}
	return objs, nil
}

// countLines counts lines in blob data.
func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte("\n"))
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// ---------------------------------------------------------------- PR helpers

// prFilesFor diffs the merge-base tree against the head tree.
func prFilesFor(repo *Repo, baseSHA, headSHA string) []PRFile {
	mb := mergeBase(repo, headSHA, baseSHA)
	var mbTree, headTree string
	if mb != "" {
		mbTree = treeOf(repo, mb)
	}
	headTree = treeOf(repo, headSHA)
	mbFiles := flattenTree(repo, mbTree)
	headFiles := flattenTree(repo, headTree)
	seen := map[string]bool{}
	var paths []string
	for p := range mbFiles {
		paths = append(paths, p)
		seen[p] = true
	}
	for p := range headFiles {
		if !seen[p] {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	var out []PRFile
	for _, p := range paths {
		b, inBase := mbFiles[p]
		h, inHead := headFiles[p]
		if inBase && inHead && b == h {
			continue
		}
		var status string
		var add, del int
		switch {
		case !inBase:
			status = "added"
			add = countLines(repo.Objects[h].Data)
		case !inHead:
			status = "removed"
			del = countLines(repo.Objects[b].Data)
		default:
			status = "modified"
			add = countLines(repo.Objects[h].Data)
			del = countLines(repo.Objects[b].Data)
		}
		if add == 0 && del == 0 {
			add = 1
		}
		out = append(out, PRFile{Path: p, Status: status, Additions: add, Deletions: del})
	}
	return out
}

// mergeConflict reports whether a three-way merge of headTip onto baseTip
// would conflict (pure: no mutation). For each file changed between the
// merge-base and the head, it conflicts when the base tip also changed it
// to different content; likewise for files deleted in the head.
func mergeConflict(repo *Repo, baseTip, headTip string) bool {
	mb := mergeBase(repo, headTip, baseTip)
	var mbTree string
	if mb != "" {
		mbTree = treeOf(repo, mb)
	}
	mbFiles := flattenTree(repo, mbTree)
	baseFiles := flattenTree(repo, treeOf(repo, baseTip))
	headFiles := flattenTree(repo, treeOf(repo, headTip))
	for p, hOID := range headFiles {
		mbOID, inMB := mbFiles[p]
		if inMB && mbOID == hOID {
			continue
		}
		if !inMB {
			if bOID, inBase := baseFiles[p]; inBase && bOID != hOID {
				return true
			}
			continue
		}
		if bOID, inBase := baseFiles[p]; inBase && bOID != mbOID && bOID != hOID {
			return true
		}
	}
	for p, mbOID := range mbFiles {
		if _, inHead := headFiles[p]; inHead {
			continue
		}
		if bOID, inBase := baseFiles[p]; inBase && bOID != mbOID {
			return true
		}
	}
	return false
}

// mergePR squash-merges a pull request with a three-way merge. Returns the
// merge commit oid, or ("", true) on conflict.
func (s *Store) mergePR(repo *Repo, pr *PR) (string, bool) {
	baseTip := repo.Refs["refs/heads/"+pr.BaseRef]
	headTip := repo.Refs["refs/heads/"+pr.HeadRef]
	if baseTip == "" || headTip == "" {
		return "", true
	}
	if mergeConflict(repo, baseTip, headTip) {
		return "", true
	}
	mb := mergeBase(repo, headTip, baseTip)
	var mbTree string
	if mb != "" {
		mbTree = treeOf(repo, mb)
	}
	mbFiles := flattenTree(repo, mbTree)
	baseFiles := flattenTree(repo, treeOf(repo, baseTip))
	headFiles := flattenTree(repo, treeOf(repo, headTip))
	merged := make(map[string]string, len(baseFiles))
	for p, oid := range baseFiles {
		merged[p] = oid
	}
	for p, hOID := range headFiles {
		mbOID, inMB := mbFiles[p]
		if inMB && mbOID == hOID {
			continue
		}
		merged[p] = hOID
	}
	for p := range mbFiles {
		if _, inHead := headFiles[p]; inHead {
			continue
		}
		delete(merged, p)
	}
	newTree := buildTree(repo, merged)
	mergeSHA := s.makeCommit(repo, newTree, []string{baseTip}, pr.Title)
	repo.Refs["refs/heads/"+pr.BaseRef] = mergeSHA
	now := s.clock.Now()
	pr.State = "closed"
	pr.Merged = true
	pr.MergedAt = now
	pr.MergeCommitSHA = mergeSHA
	pr.BaseSHA = mergeSHA
	pr.UpdatedAt = now
	pr.cached = nil
	s.bumpGen()
	return mergeSHA, false
}

// ---------------------------------------------------------------- HTTP handlers

// gitRoute dispatches /{owner}/{repo}.git/* requests.
func (cc *conn) gitRoute() {
	r := &cc.req
	segs := splitPath(r.path)
	if len(segs) < 3 || !strings.HasSuffix(segs[1], ".git") {
		cc.notFound("")
		return
	}
	owner := segs[0]
	repoName := segs[1][:len(segs[1])-len(".git")]
	// A repository under any other owner is 404, never 403.
	if owner != viewerLogin {
		cc.notFound("repository not found")
		return
	}
	cc.store.mu.RLock()
	repo := cc.store.getRepo(owner, repoName)
	cc.store.mu.RUnlock()
	if repo == nil {
		cc.notFound("repository not found")
		return
	}
	switch segs[2] {
	case "info":
		if len(segs) == 4 && segs[3] == "refs" && r.method == "GET" {
			cc.gitInfoRefs(repo)
			return
		}
	case "git-upload-pack":
		if len(segs) == 3 && r.method == "POST" {
			cc.gitUploadPack(repo)
			return
		}
	case "git-receive-pack":
		if len(segs) == 3 && r.method == "POST" {
			cc.gitReceivePack(repo)
			return
		}
	}
	cc.notFound("")
}

// advertRefLines renders the ref lines of a v0 advertisement (HEAD first,
// then refs sorted, then peeled tags).
func advertRefLines(repo *Repo, caps string) []byte {
	var b []byte
	head := repo.headOID()
	if head == "" {
		// Unborn: a single capabilities line.
		b = pktLine(b, []byte(zeroOID+" capabilities^{}\x00"+caps+"\n"))
		return pktFlush(b)
	}
	b = pktLine(b, []byte(head+" HEAD\x00"+caps+"\n"))
	for _, name := range repo.refNames() {
		oid := repo.Refs[name]
		b = pktLine(b, []byte(oid+" "+name+"\n"))
	}
	// Peeled annotated tags.
	for _, name := range repo.refNames() {
		if !strings.HasPrefix(name, "refs/tags/") {
			continue
		}
		obj := repo.Objects[repo.Refs[name]]
		if obj == nil || obj.Type != "tag" {
			continue
		}
		if target := parseTagTarget(obj.Data); target != "" {
			if tobj := repo.Objects[target]; tobj != nil && tobj.Type == "commit" {
				b = pktLine(b, []byte(target+" "+name+"^{}\n"))
			}
		}
	}
	return pktFlush(b)
}

// gitInfoRefs answers GET /info/refs?service=...
func (cc *conn) gitInfoRefs(repo *Repo) {
	r := &cc.req
	service := r.qval("service")
	gen := cc.store.gen.Load()
	switch service {
	case "git-upload-pack":
		if r.gitProtocol == "version=2" {
			// The v2 advertisement is constant: capabilities only.
			body := v2Advert()
			cc.writeResp(200, "application/x-git-upload-pack-advertisement", body)
			return
		}
		key := "up0:" + repoKey(repo.Owner, repo.Name)
		cc.store.fetchMu.RLock()
		if e := cc.store.advertC[key]; e != nil && e.gen == gen {
			body := e.body
			cc.store.fetchMu.RUnlock()
			cc.writeResp(200, "application/x-git-upload-pack-advertisement", body)
			return
		}
		cc.store.fetchMu.RUnlock()
		cc.store.fetchMu.Lock()
		if e := cc.store.advertC[key]; e != nil && e.gen == gen {
			body := e.body
			cc.store.fetchMu.Unlock()
			cc.writeResp(200, "application/x-git-upload-pack-advertisement", body)
			return
		}
		cc.store.mu.RLock()
		caps := "side-band-64k thin-pack ofs-delta symref=HEAD:refs/heads/main agent=forge/1.0"
		body := pktLine(nil, []byte("# service=git-upload-pack\n"))
		body = append(body, advertRefLines(repo, caps)...)
		cc.store.mu.RUnlock()
		cc.store.advertC[key] = &cacheEntry{gen: gen, body: body}
		cc.store.fetchMu.Unlock()
		cc.writeResp(200, "application/x-git-upload-pack-advertisement", body)
	case "git-receive-pack":
		key := "rp0:" + repoKey(repo.Owner, repo.Name)
		cc.store.fetchMu.RLock()
		if e := cc.store.advertC[key]; e != nil && e.gen == gen {
			body := e.body
			cc.store.fetchMu.RUnlock()
			cc.writeResp(200, "application/x-git-receive-pack-advertisement", body)
			return
		}
		cc.store.fetchMu.RUnlock()
		cc.store.fetchMu.Lock()
		if e := cc.store.advertC[key]; e != nil && e.gen == gen {
			body := e.body
			cc.store.fetchMu.Unlock()
			cc.writeResp(200, "application/x-git-receive-pack-advertisement", body)
			return
		}
		cc.store.mu.RLock()
		caps := "report-status side-band-64k delete-refs agent=forge/1.0"
		body := pktLine(nil, []byte("# service=git-receive-pack\n"))
		body = append(body, advertRefLines(repo, caps)...)
		cc.store.mu.RUnlock()
		cc.store.advertC[key] = &cacheEntry{gen: gen, body: body}
		cc.store.fetchMu.Unlock()
		cc.writeResp(200, "application/x-git-receive-pack-advertisement", body)
	default:
		cc.notFound("unknown service")
	}
}

// v2Advert is the constant protocol-v2 advertisement. It starts directly
// with "version 2": a "# service=..." preamble here makes real git clients
// reject the advertisement (the preamble belongs to v0 only).
// v2AdvertBytes is the constant protocol-v2 advertisement, built once.
// writeResp copies the body into the per-connection buffer and never
// mutates it, so sharing this slice across requests is safe.
var v2AdvertBytes = func() []byte {
	var b []byte
	b = pktLine(b, []byte("version 2\n"))
	b = pktLine(b, []byte("ls-refs=unborn\n"))
	b = pktLine(b, []byte("fetch=shallow\n"))
	b = pktLine(b, []byte("object-format=sha1\n"))
	b = pktLine(b, []byte("agent=forge/1.0\n"))
	return pktFlush(b)
}()

func v2Advert() []byte {
	return v2AdvertBytes
}

// gitUploadPack answers POST git-upload-pack (protocol v2: ls-refs, fetch).
func (cc *conn) gitUploadPack(repo *Repo) {
	r := &cc.req
	payloads, kinds, err := parsePktLines(r.body)
	if err != nil {
		cc.writeJSON(400, errorJSON("malformed pkt-line body"))
		return
	}
	// The command is the first line: "command=ls-refs" or "command=fetch".
	// Pkt-line payloads keep their trailing newline: trim it.
	var command string
	for i, p := range payloads {
		if kinds[i] != "line" {
			break
		}
		if strings.HasPrefix(string(p), "command=") {
			command = strings.TrimRight(string(p[len("command="):]), "\r\n")
			break
		}
	}
	switch command {
	case "ls-refs":
		cc.gitLsRefs(repo, payloads, kinds)
	case "fetch":
		cc.gitFetch(repo, payloads, kinds)
	default:
		cc.writeJSON(400, errorJSON("unknown upload-pack command"))
	}
}

// lsRefsArgs are the arguments after the delim of an ls-refs request.
type lsRefsArgs struct {
	peel      bool
	symrefs   bool
	unborn    bool
	prefixes  []string
}

// gitLsRefs answers a v2 ls-refs command.
func (cc *conn) gitLsRefs(repo *Repo, payloads [][]byte, kinds []string) {
	var args lsRefsArgs
	inArgs := false
	for i, p := range payloads {
		switch kinds[i] {
		case "delim":
			inArgs = true
		case "line":
			if !inArgs {
				continue
			}
			s := strings.TrimRight(string(p), "\r\n")
			switch {
			case s == "peel":
				args.peel = true
			case s == "symrefs":
				args.symrefs = true
			case s == "unborn":
				args.unborn = true
			case strings.HasPrefix(s, "ref-prefix "):
				args.prefixes = append(args.prefixes, s[len("ref-prefix "):])
			}
		}
	}
	key := "ls:" + repoKey(repo.Owner, repo.Name) + "|" + string(cc.req.body)
	gen := cc.store.gen.Load()
	cc.store.fetchMu.RLock()
	if e := cc.store.lsrefsC[key]; e != nil && e.gen == gen {
		body := e.body
		cc.store.fetchMu.RUnlock()
		cc.writeResp(200, "application/x-git-upload-pack-result", body)
		return
	}
	cc.store.fetchMu.RUnlock()
	cc.store.fetchMu.Lock()
	if e := cc.store.lsrefsC[key]; e != nil && e.gen == gen {
		body := e.body
		cc.store.fetchMu.Unlock()
		cc.writeResp(200, "application/x-git-upload-pack-result", body)
		return
	}
	cc.store.mu.RLock()
	body := buildLsRefs(repo, &args)
	cc.store.mu.RUnlock()
	cc.store.lsrefsC[key] = &cacheEntry{gen: gen, body: body}
	cc.store.fetchMu.Unlock()
	cc.writeResp(200, "application/x-git-upload-pack-result", body)
}

// buildLsRefs renders the ls-refs response for the current ref state.
func buildLsRefs(repo *Repo, args *lsRefsArgs) []byte {
	var b []byte
	head := repo.headOID()
	// HEAD is listed only when no ref-prefix filter is given.
	if len(args.prefixes) == 0 {
		if head == "" {
			if args.unborn {
				b = pktLine(b, []byte("unborn HEAD symref-target:refs/heads/main\n"))
			}
		} else {
			line := head + " HEAD"
			if args.symrefs {
				line += " symref-target:refs/heads/main"
			}
			b = pktLine(b, []byte(line+"\n"))
		}
	}
	for _, name := range repo.refNames() {
		if len(args.prefixes) > 0 {
			matched := false
			for _, p := range args.prefixes {
				if strings.HasPrefix(name, p) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		oid := repo.Refs[name]
		line := oid + " " + name
		if args.peel && strings.HasPrefix(name, "refs/tags/") {
			if obj := repo.Objects[oid]; obj != nil && obj.Type == "tag" {
				if target := parseTagTarget(obj.Data); target != "" {
					if tobj := repo.Objects[target]; tobj != nil && tobj.Type == "commit" {
						line += " peeled:" + target
					}
				}
			}
		}
		b = pktLine(b, []byte(line+"\n"))
	}
	return pktFlush(b)
}

// fetchArgs are the arguments of a v2 fetch command.
type fetchArgs struct {
	wants    []string
	haves    []string
	shallows []string
	depth    int
}

// gitFetch answers a v2 fetch command.
func (cc *conn) gitFetch(repo *Repo, payloads [][]byte, kinds []string) {
	var args fetchArgs
	inArgs := false
	for i, p := range payloads {
		switch kinds[i] {
		case "delim":
			inArgs = true
		case "line":
			if !inArgs {
				continue
			}
			s := strings.TrimRight(string(p), "\r\n")
			switch {
			case strings.HasPrefix(s, "want "):
				args.wants = append(args.wants, s[len("want "):])
			case strings.HasPrefix(s, "have "):
				args.haves = append(args.haves, s[len("have "):])
			case strings.HasPrefix(s, "shallow "):
				args.shallows = append(args.shallows, s[len("shallow "):])
			case strings.HasPrefix(s, "deepen "):
				if n, err := strconv.Atoi(strings.TrimSpace(s[len("deepen "):])); err == nil && n > 0 {
					args.depth = n
				}
			}
		}
	}
	// Cache key: repo generation + the full request shape.
	keyParts := make([]string, 0, len(args.wants)+len(args.haves)+len(args.shallows)+4)
	keyParts = append(keyParts, repoKey(repo.Owner, repo.Name))
	sorted := append([]string{}, args.wants...)
	sort.Strings(sorted)
	keyParts = append(keyParts, sorted...)
	keyParts = append(keyParts, "|")
	sorted = append([]string{}, args.haves...)
	sort.Strings(sorted)
	keyParts = append(keyParts, sorted...)
	keyParts = append(keyParts, "|")
	sorted = append([]string{}, args.shallows...)
	sort.Strings(sorted)
	keyParts = append(keyParts, sorted...)
	keyParts = append(keyParts, "|"+strconv.Itoa(args.depth))
	key := strings.Join(keyParts, "\x00")

	gen := cc.store.gen.Load()
	cc.store.fetchMu.RLock()
	if e := cc.store.fetchC[key]; e != nil && e.gen == gen {
		body := e.body
		cc.store.fetchMu.RUnlock()
		cc.writeResp(200, "application/x-git-upload-pack-result", body)
		return
	}
	cc.store.fetchMu.RUnlock()
	cc.store.fetchMu.Lock()
	if e := cc.store.fetchC[key]; e != nil && e.gen == gen {
		body := e.body
		cc.store.fetchMu.Unlock()
		cc.writeResp(200, "application/x-git-upload-pack-result", body)
		return
	}
	cc.store.mu.RLock()
	body := buildFetch(repo, &args)
	cc.store.mu.RUnlock()
	cc.store.fetchC[key] = &cacheEntry{gen: gen, body: body}
	cc.store.fetchMu.Unlock()
	cc.writeResp(200, "application/x-git-upload-pack-result", body)
}

// buildFetch computes the fetch response: acknowledgments, optional
// shallow-info, and the packfile section with sideband framing.
func buildFetch(repo *Repo, args *fetchArgs) []byte {
	wantSet, wantDist := collectReachable(repo, args.wants, args.depth, nil)
	shallowSet := map[string]bool{}
	for _, s := range args.shallows {
		shallowSet[s] = true
	}
	haveSet, _ := collectReachable(repo, args.haves, 0, shallowSet)
	var send []string
	for oid := range wantSet {
		if !haveSet[oid] {
			send = append(send, oid)
		}
	}
	sort.Strings(send)
	objs := make([]*GitObject, 0, len(send))
	for _, oid := range send {
		if obj := repo.Objects[oid]; obj != nil {
			objs = append(objs, obj)
		}
	}
	var b []byte
	b = pktLine(b, []byte("acknowledgments\n"))
	b = pktLine(b, []byte("NAK\n"))
	b = pktDelim(b)
	if args.depth > 0 {
		// New shallow boundary: commits in the send set at distance depth-1.
		b = pktLine(b, []byte("shallow-info\n"))
		for _, oid := range send {
			if d, ok := wantDist[oid]; ok && d == args.depth-1 {
				if obj := repo.Objects[oid]; obj != nil && obj.Type == "commit" {
					b = pktLine(b, []byte("shallow "+oid+"\n"))
				}
			}
		}
		// A requested shallow commit whose parent entered the send set is
		// no longer shallow.
		sendSet := map[string]bool{}
		for _, oid := range send {
			sendSet[oid] = true
		}
		for _, s := range args.shallows {
			if obj := repo.Objects[s]; obj != nil && obj.Type == "commit" {
				for _, p := range obj.parents {
					if sendSet[p] {
						b = pktLine(b, []byte("unshallow "+s+"\n"))
						break
					}
				}
			}
		}
		b = pktDelim(b)
	}
	b = pktLine(b, []byte("packfile\n"))
	pack := writePack(nil, objs)
	// Sideband: band 1, chunks of at most 65515 data bytes.
	for len(pack) > 0 {
		n := len(pack)
		if n > 65515 {
			n = 65515
		}
		payload := make([]byte, 0, n+1)
		payload = append(payload, 1)
		payload = append(payload, pack[:n]...)
		b = pktLine(b, payload)
		pack = pack[n:]
	}
	return pktFlush(b)
}

// pushCommand is one receive-pack ref update.
type pushCommand struct {
	old, new, ref string
}

// gitReceivePack answers POST git-receive-pack (protocol v0).
func (cc *conn) gitReceivePack(repo *Repo) {
	r := &cc.req
	// Parse command pkt-lines until the flush; everything after the flush
	// is the raw pack (it is not pkt-line framed, so it must not be
	// parsed as pkt-lines).
	var commands []pushCommand
	packStart := len(r.body)
	off := 0
	malformed := false
	for off+4 <= len(r.body) {
		n := pktLenValue(r.body[off : off+4])
		if n < 0 || n < 4 && n != 0 && n != 1 {
			malformed = true
			break
		}
		if n == 0 {
			packStart = off + 4
			break
		}
		if n == 1 {
			off += 4
			continue
		}
		if off+n > len(r.body) {
			malformed = true
			break
		}
		line := string(r.body[off+4 : off+n])
		if nul := strings.IndexByte(line, 0); nul >= 0 {
			line = line[:nul]
		}
		fields := strings.Fields(line)
		if len(fields) == 3 {
			commands = append(commands, pushCommand{old: fields[0], new: fields[1], ref: fields[2]})
		}
		off += n
	}
	if malformed {
		cc.writeJSON(400, errorJSON("malformed pkt-line body"))
		return
	}
	var pack []byte
	if packStart < len(r.body) {
		pack = r.body[packStart:]
	}
	cc.store.mu.Lock()
	defer cc.store.mu.Unlock()
	var unpackErr error
	if len(pack) > 0 {
		objs, err := readPack(pack)
		if err != nil {
			unpackErr = err
		} else {
			for _, o := range objs {
				repo.Objects[o.OID] = o
			}
			cc.store.bumpGen()
		}
	}
	// Build the report inside band 1, pkt-line framed.
	var report []byte
	if unpackErr != nil {
		report = pktLine(report, []byte("unpack "+unpackErr.Error()+"\n"))
	} else {
		report = pktLine(report, []byte("unpack ok\n"))
	}
	for _, cmd := range commands {
		ok, reason := applyPush(repo, cmd, unpackErr != nil)
		if ok {
			report = pktLine(report, []byte("ok "+cmd.ref+"\n"))
		} else {
			report = pktLine(report, []byte("ng "+cmd.ref+" "+reason+"\n"))
		}
	}
	var body []byte
	body = pktLine(body, append([]byte{1}, report...))
	body = pktFlush(body)
	cc.writeResp(200, "application/x-git-receive-pack-result", body)
}

// pktLenValue decodes a 4-hex-digit pkt-line length; -1 when invalid.
func pktLenValue(b []byte) int {
	n := 0
	for j := 0; j < 4; j++ {
		c := b[j]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'f':
			v = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = int(c-'A') + 10
		default:
			return -1
		}
		n = n*16 + v
	}
	return n
}

// applyPush applies one ref update under the fast-forward-only rule.
// Returns (ok, reason).
func applyPush(repo *Repo, cmd pushCommand, unpackFailed bool) (bool, string) {
	if unpackFailed {
		return false, "unpack failed"
	}
	if cmd.new == zeroOID {
		// Delete.
		if _, exists := repo.Refs[cmd.ref]; !exists {
			return false, "reference does not exist"
		}
		delete(repo.Refs, cmd.ref)
		return true, ""
	}
	if cmd.old == zeroOID {
		// Create.
		if _, exists := repo.Refs[cmd.ref]; exists {
			return false, "reference already exists"
		}
		if _, ok := repo.Objects[cmd.new]; !ok {
			return false, "object not found"
		}
		repo.Refs[cmd.ref] = cmd.new
		return true, ""
	}
	// Update.
	cur, exists := repo.Refs[cmd.ref]
	if !exists {
		return false, "reference does not exist"
	}
	if cur != cmd.old {
		return false, "non-fast-forward"
	}
	if _, ok := repo.Objects[cmd.new]; !ok {
		return false, "object not found"
	}
	if !isAncestor(repo, cmd.old, cmd.new) {
		return false, "non-fast-forward"
	}
	repo.Refs[cmd.ref] = cmd.new
	return true, ""
}
