package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestAggregateIssues(t *testing.T) {
	issues := func(issues ...issue) []issue {
		return issues
	}
	ignoredIssue := func(id, severity, title string) issue {
		return issue{
			ID: id,
			IssueData: issueData{
				Severity: severity,
				Title:    title,
			},
			Ignored: true,
		}
	}
	iss := func(id, severity, title string) issue {
		return issue{
			ID: id,
			IssueData: issueData{
				Severity: severity,
				Title:    title,
			},
		}
	}
	aggregateResults := func(aggregateResults ...aggregateResult) []aggregateResult {
		return aggregateResults
	}
	result := func(severity, title string, count int, ignored bool) aggregateResult {
		return aggregateResult{
			severity: severity,
			title:    title,
			count:    count,
			ignored:  ignored,
		}
	}
	tt := []struct {
		name       string
		issues     []issue
		aggregates []aggregateResult
	}{
		{
			name:       "nil issues",
			issues:     nil,
			aggregates: nil,
		},
		{
			name:       "single issue",
			issues:     issues(iss("iss-1", "high", "DDoS")),
			aggregates: aggregateResults(result("high", "DDoS", 1, false)),
		},
		{
			name: "multiple of different severity and same title",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				iss("iss-2", "low", "DDoS"),
			),
			aggregates: aggregateResults(
				result("high", "DDoS", 1, false),
				result("low", "DDoS", 1, false),
			),
		},
		{
			name: "multiple of same severity and title",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				iss("iss-2", "high", "DDoS"),
			),
			aggregates: aggregateResults(
				result("high", "DDoS", 2, false),
			),
		},
		{
			name: "multiple of same severity and title but some ignored",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				ignoredIssue("iss-2", "high", "DDoS"),
			),
			aggregates: aggregateResults(
				result("high", "DDoS", 1, false),
				result("high", "DDoS", 1, true),
			),
		},
		{
			name: "multiple of same severity different title",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				iss("iss-2", "high", "ReDoS"),
			),
			aggregates: aggregateResults(
				result("high", "DDoS", 1, false),
				result("high", "ReDoS", 1, false),
			),
		},
		{
			name: "multiple of same severity different title some ignored",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				ignoredIssue("iss-2", "high", "ReDoS"),
			),
			aggregates: aggregateResults(
				result("high", "DDoS", 1, false),
				result("high", "ReDoS", 1, true),
			),
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			output := aggregateIssues(tc.issues)
			if len(output) != len(tc.aggregates) {
				t.Logf("output: %v\n", output)
				t.Errorf("Length of aggregate results not as expected: expected %d got %d", len(tc.aggregates), len(output))
				return
			}
			// sort as aggregateIssues does not provide a stable ordered slice
			sort.Slice(output, func(i, j int) bool {
				return aggregationKey(issue{
					IssueData: issueData{
						Severity: output[i].severity,
						Title:    output[i].title,
					},
					Ignored: output[i].ignored,
				}) < aggregationKey(issue{
					IssueData: issueData{
						Severity: output[j].severity,
						Title:    output[j].title,
					},
					Ignored: output[j].ignored,
				})
			})
			if !reflect.DeepEqual(output, tc.aggregates) {
				t.Errorf("Aggregates are not matching expectations: expected %v got %v", tc.aggregates, output)
			}
		})
	}
}

func TestRunAPIPolling_issuesTimeout(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		calls++
		// allow organizations call to succeed
		if calls == 1 {
			//nolint:errcheck
			rw.Write([]byte(`{
				"orgs": [{
					"id": "id",
					"name": "name"
				}]
			}`))
			return
		}
		time.Sleep(1 * time.Second)
		rw.WriteHeader(http.StatusOK)
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := runAPIPolling(ctx, server.URL, "token", nil, 20*time.Millisecond, 1*time.Millisecond)
		if err != nil {
			t.Errorf("unexpected error result: %v", err)
		}
	}()

	// stop the polling again after 100ms
	<-time.After(100 * time.Millisecond)
	cancel()

	// wait for the polling to stop
	wg.Wait()

	if !ready {
		t.Fatalf("Ready not set but it should be")
	}
}
