// JSON rendering: hand-rolled byte appenders (no encoding/json on the hot
// paths) plus the REST object renderers. Rendered issue/repo/PR JSON is
// cached on the object and invalidated on mutation.
package main

import (
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- appenders

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0')
				dst = append(dst, "0123456789abcdef"[c>>4], "0123456789abcdef"[c&0xf])
			} else {
				dst = append(dst, c)
			}
		}
	}
	return append(dst, '"')
}

func appendJSONInt(dst []byte, n int64) []byte {
	return strconv.AppendInt(dst, n, 10)
}

func appendJSONBool(dst []byte, b bool) []byte {
	if b {
		return append(dst, "true"...)
	}
	return append(dst, "false"...)
}

// isoTime renders a deterministic millisecond timestamp as RFC 3339 UTC.
func isoTime(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func appendJSONTime(dst []byte, ms int64) []byte {
	return appendJSONString(dst, isoTime(ms))
}

// ---------------------------------------------------------------- object JSON

func userJSON(login string, id int64) []byte {
	b := make([]byte, 0, 96)
	b = append(b, `{"login":`...)
	b = appendJSONString(b, login)
	b = append(b, `,"id":`...)
	b = appendJSONInt(b, id)
	b = append(b, `,"type":"User"}`...)
	return b
}

// repoJSON renders a repository object; cached on the repo.
func repoJSON(r *Repo, origin string) []byte {
	if r.cached != nil {
		return r.cached
	}
	b := make([]byte, 0, 512)
	b = append(b, `{"id":`...)
	b = appendJSONInt(b, r.ID)
	b = append(b, `,"name":`...)
	b = appendJSONString(b, r.Name)
	b = append(b, `,"full_name":`...)
	b = appendJSONString(b, r.Owner+"/"+r.Name)
	b = append(b, `,"owner":`...)
	b = append(b, userJSON(r.Owner, viewerID)...)
	b = append(b, `,"private":`...)
	b = appendJSONBool(b, r.Private)
	b = append(b, `,"description":`...)
	if r.Description == "" {
		b = append(b, "null"...)
	} else {
		b = appendJSONString(b, r.Description)
	}
	b = append(b, `,"default_branch":`...)
	b = appendJSONString(b, r.DefaultBranch)
	b = append(b, `,"created_at":`...)
	b = appendJSONTime(b, r.CreatedAt)
	b = append(b, `,"updated_at":`...)
	b = appendJSONTime(b, r.UpdatedAt)
	b = append(b, `,"html_url":`...)
	b = appendJSONString(b, origin+"/"+r.Owner+"/"+r.Name)
	b = append(b, `,"clone_url":`...)
	b = appendJSONString(b, origin+"/"+r.Owner+"/"+r.Name+".git")
	b = append(b, `,"has_issues":true,"has_projects":true,"has_wiki":true,"fork":false,"archived":false,"disabled":false,"visibility":`...)
	if r.Private {
		b = append(b, `"private"`...)
	} else {
		b = append(b, `"public"`...)
	}
	b = append(b, `,"topics":[]}`...)
	r.cached = b
	return b
}

// issueJSON renders an issue object; cached on the issue.
func issueJSON(iss *Issue) []byte {
	if iss.cached != nil {
		return iss.cached
	}
	b := make([]byte, 0, 384)
	b = append(b, `{"id":`...)
	b = appendJSONInt(b, iss.ID)
	b = append(b, `,"number":`...)
	b = appendJSONInt(b, int64(iss.Number))
	b = append(b, `,"title":`...)
	b = appendJSONString(b, iss.Title)
	b = append(b, `,"body":`...)
	b = appendJSONString(b, iss.Body)
	b = append(b, `,"state":`...)
	b = appendJSONString(b, iss.State)
	b = append(b, `,"labels":[`...)
	for i, l := range iss.Labels {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"name":`...)
		b = appendJSONString(b, l.Name)
		b = append(b, `,"color":`...)
		b = appendJSONString(b, l.Color)
		b = append(b, `}`...)
	}
	b = append(b, `],"created_at":`...)
	b = appendJSONTime(b, iss.CreatedAt)
	b = append(b, `,"updated_at":`...)
	b = appendJSONTime(b, iss.UpdatedAt)
	b = append(b, `,"user":`...)
	b = append(b, userJSON(viewerLogin, viewerID)...)
	b = append(b, `,"assignee":null,"assignees":[],"comments":`...)
	b = appendJSONInt(b, int64(len(iss.Comments)))
	b = append(b, `}`...)
	iss.cached = b
	return b
}

// commentJSON renders a comment object.
func commentJSON(c *Comment) []byte {
	b := make([]byte, 0, 192)
	b = append(b, `{"id":`...)
	b = appendJSONInt(b, c.ID)
	b = append(b, `,"body":`...)
	b = appendJSONString(b, c.Body)
	b = append(b, `,"created_at":`...)
	b = appendJSONTime(b, c.CreatedAt)
	b = append(b, `,"updated_at":`...)
	b = appendJSONTime(b, c.UpdatedAt)
	b = append(b, `,"user":`...)
	b = append(b, userJSON(viewerLogin, viewerID)...)
	b = append(b, `}`...)
	return b
}

// prJSON renders a pull request object; cached on the PR.
func prJSON(pr *PR) []byte {
	if pr.cached != nil {
		return pr.cached
	}
	b := make([]byte, 0, 512)
	b = append(b, `{"id":`...)
	b = appendJSONInt(b, pr.ID)
	b = append(b, `,"number":`...)
	b = appendJSONInt(b, int64(pr.Number))
	b = append(b, `,"title":`...)
	b = appendJSONString(b, pr.Title)
	b = append(b, `,"body":`...)
	b = appendJSONString(b, pr.Body)
	b = append(b, `,"state":`...)
	b = appendJSONString(b, pr.State)
	b = append(b, `,"merged":`...)
	b = appendJSONBool(b, pr.Merged)
	b = append(b, `,"merged_at":`...)
	if pr.Merged {
		b = appendJSONTime(b, pr.MergedAt)
	} else {
		b = append(b, "null"...)
	}
	b = append(b, `,"merge_commit_sha":`...)
	if pr.MergeCommitSHA == "" {
		b = append(b, "null"...)
	} else {
		b = appendJSONString(b, pr.MergeCommitSHA)
	}
	b = append(b, `,"head":{"ref":`...)
	b = appendJSONString(b, pr.HeadRef)
	b = append(b, `,"sha":`...)
	b = appendJSONString(b, pr.HeadSHA)
	b = append(b, `,"label":`...)
	b = appendJSONString(b, viewerLogin+":"+pr.HeadRef)
	b = append(b, `},"base":{"ref":`...)
	b = appendJSONString(b, pr.BaseRef)
	b = append(b, `,"sha":`...)
	b = appendJSONString(b, pr.BaseSHA)
	b = append(b, `,"label":`...)
	b = appendJSONString(b, viewerLogin+":"+pr.BaseRef)
	b = append(b, `},"created_at":`...)
	b = appendJSONTime(b, pr.CreatedAt)
	b = append(b, `,"updated_at":`...)
	b = appendJSONTime(b, pr.UpdatedAt)
	b = append(b, `,"user":`...)
	b = append(b, userJSON(viewerLogin, viewerID)...)
	b = append(b, `,"draft":false,"mergeable":true,"mergeable_state":"clean"}`...)
	pr.cached = b
	return b
}

// labelJSON renders a label object.
func labelJSON(l *Label) []byte {
	b := make([]byte, 0, 64)
	b = append(b, `{"name":`...)
	b = appendJSONString(b, l.Name)
	b = append(b, `,"color":`...)
	b = appendJSONString(b, l.Color)
	b = append(b, `,"description":""}`...)
	return b
}

// branchJSON renders a branch object.
func branchJSON(name, sha string) []byte {
	b := make([]byte, 0, 128)
	b = append(b, `{"name":`...)
	b = appendJSONString(b, name)
	b = append(b, `,"commit":{"sha":`...)
	b = appendJSONString(b, sha)
	b = append(b, `},"protected":false}`...)
	return b
}

// commitListJSON renders one commit-list entry from stored commit bytes.
func commitListJSON(oid string, obj *GitObject) []byte {
	msg := commitMessage(obj.Data)
	aName, aEmail, aTs := commitIdentity(obj.Data, "author")
	cName, cEmail, cTs := commitIdentity(obj.Data, "committer")
	if aName == "" {
		aName, aEmail, aTs = cName, cEmail, cTs
	}
	if cName == "" {
		cName, cEmail, cTs = aName, aEmail, aTs
	}
	b := make([]byte, 0, 320)
	b = append(b, `{"sha":`...)
	b = appendJSONString(b, oid)
	b = append(b, `,"commit":{"message":`...)
	b = appendJSONString(b, strings.TrimRight(msg, "\n"))
	b = append(b, `,"author":{"name":`...)
	b = appendJSONString(b, aName)
	b = append(b, `,"email":`...)
	b = appendJSONString(b, aEmail)
	b = append(b, `,"date":`...)
	b = appendJSONTime(b, aTs*1000)
	b = append(b, `},"committer":{"name":`...)
	b = appendJSONString(b, cName)
	b = append(b, `,"email":`...)
	b = appendJSONString(b, cEmail)
	b = append(b, `,"date":`...)
	b = appendJSONTime(b, cTs*1000)
	b = append(b, `}},"author":`...)
	b = append(b, userJSON(viewerLogin, viewerID)...)
	b = append(b, `,"committer":`...)
	b = append(b, userJSON(viewerLogin, viewerID)...)
	b = append(b, `}`...)
	return b
}

// errorJSON renders {"message": "..."}.
func errorJSON(msg string) []byte {
	b := make([]byte, 0, len(msg)+16)
	b = append(b, `{"message":`...)
	b = appendJSONString(b, msg)
	b = append(b, '}')
	return b
}
