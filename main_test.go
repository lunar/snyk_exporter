package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestAggregateVulnerabilities(t *testing.T) {
	vulnerabilities := func(vulnerabilities ...vulnerability) []vulnerability {
		return vulnerabilities
	}
	vulnerability := func(id, severity, title string) vulnerability {
		return vulnerability{
			ID:       id,
			Severity: severity,
			Title:    title,
		}
	}
	aggregateResults := func(aggregateResults ...aggregateResult) []aggregateResult {
		return aggregateResults
	}
	result := func(severity, title string, count int) aggregateResult {
		return aggregateResult{
			severity: severity,
			title:    title,
			count:    count,
		}
	}
	tt := []struct {
		name       string
		issues     issues
		aggregates []aggregateResult
	}{
		{
			name: "nil vulnerabilities",
			issues: issues{
				Vulnerabilities: nil,
			},
			aggregates: nil,
		},
		{
			name: "single vulnerabilities",
			issues: issues{
				Vulnerabilities: vulnerabilities(vulnerability("vul-1", "high", "DDoS")),
			},
			aggregates: aggregateResults(result("high", "DDoS", 1)),
		},
		{
			name: "multiple of different severity and same title",
			issues: issues{
				Vulnerabilities: vulnerabilities(
					vulnerability("vul-1", "high", "DDoS"),
					vulnerability("vul-2", "low", "DDoS"),
				),
			},
			aggregates: aggregateResults(
				result("high", "DDoS", 1),
				result("low", "DDoS", 1),
			),
		},
		{
			name: "multiple of same severity and title",
			issues: issues{
				Vulnerabilities: vulnerabilities(
					vulnerability("vul-1", "high", "DDoS"),
					vulnerability("vul-2", "high", "DDoS"),
				),
			},
			aggregates: aggregateResults(
				result("high", "DDoS", 2),
			),
		},
		{
			name: "multiple of same severity different title",
			issues: issues{
				Vulnerabilities: vulnerabilities(
					vulnerability("vul-1", "high", "DDoS"),
					vulnerability("vul-2", "high", "ReDoS"),
				),
			},
			aggregates: aggregateResults(
				result("high", "DDoS", 1),
				result("high", "ReDoS", 1),
			),
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			output := aggregateVulnerabilities(tc.issues)
			if len(output) != len(tc.aggregates) {
				t.Logf("output: %v\n", output)
				t.Errorf("Length of aggregate results not as expected: expected %d got %d", len(tc.aggregates), len(output))
				return
			}
			// sort as aggregateVulnerabilities does not provide a stable ordered
			// slice
			sort.Slice(output, func(i, j int) bool {
				return output[i].title < output[j].title
			})
			sort.Slice(output, func(i, j int) bool {
				return output[i].severity < output[j].severity
			})
			if !reflect.DeepEqual(output, tc.aggregates) {
				t.Errorf("Aggregates are not matching expectations: expected %v got %v", tc.aggregates, output)
			}
		})
	}
}
