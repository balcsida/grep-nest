package repository

import (
	"context"
	"strings"
	"testing"

	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/pkg/api"
)

type scipCommitReader struct {
	commit string
}

func (reader *scipCommitReader) SCIPIndexCommit(context.Context, int64) (string, error) {
	return reader.commit, nil
}

// Search health says nothing about SCIP, so status must report SCIP separately; without
// it a caller cannot tell why navigation fails on a repository that reports as indexed.
func TestStatusReportsSCIPStateSeparatelyFromSearch(t *testing.T) {
	indexed := strings.Repeat("a", 40)
	older := strings.Repeat("b", 40)
	principal := authn.Principal{InstallationID: 10, RepositoryIDs: []int64{101}}

	for _, testCase := range []struct {
		name       string
		reader     SCIPIndexReader
		wantStatus string
		wantCommit string
	}{
		{"no reader wired", nil, api.SCIPStatusUnknown, ""},
		{"never uploaded", &scipCommitReader{commit: ""}, api.SCIPStatusAbsent, ""},
		{"built for an earlier commit", &scipCommitReader{commit: older}, api.SCIPStatusStale, older},
		{"matches indexed revision", &scipCommitReader{commit: indexed}, api.SCIPStatusCurrent, indexed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store := &serviceStore{repository: Repository{ID: 1, GitHubID: 101, Name: "acme/one", IndexedSHA: indexed, SearchNode: "node-a"}}
			got, err := (&Service{Store: store, SCIP: testCase.reader}).Status(t.Context(), principal, 101)
			if err != nil {
				t.Fatal(err)
			}
			if got.IndexedSHA != indexed {
				t.Fatalf("IndexedSHA = %q, want %q", got.IndexedSHA, indexed)
			}
			if got.SCIPStatus != testCase.wantStatus || got.SCIPCommit != testCase.wantCommit {
				t.Fatalf("SCIPStatus = %q commit %q, want %q / %q", got.SCIPStatus, got.SCIPCommit, testCase.wantStatus, testCase.wantCommit)
			}
		})
	}
}
