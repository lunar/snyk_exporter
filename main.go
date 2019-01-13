package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	projectLabel      = "project"
	issueTitleLabel   = "issue_title"
	severityLabel     = "severity"
	organizationLabel = "organization"
)

var (
	vulnerabilityGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "snyk_vulnerabilities_total",
			Help: "Gauge of Snyk vulnerabilities",
		},
		[]string{organizationLabel, projectLabel, issueTitleLabel, severityLabel},
	)
)

var (
	version = ""
)

func main() {
	flags := kingpin.New("snyk_exporter", "Snyk exporter for Prometheus. Provide your Snyk API token and the organization(s) to scrape to expose Prometheus metrics.")
	snykAPIURL := flags.Flag("snyk.api-url", "Snyk API URL").Default("https://snyk.io/api/v1").String()
	snykAPIToken := flags.Flag("snyk.api-token", "Snyk API token").Required().String()
	snykInterval := flags.Flag("snyk.interval", "Polling interval for requesting data from Snyk API in seconds").Short('i').Default("60").Int()
	snykOrganizations := flags.Flag("snyk.organization", "Snyk organization ID to scrape projects from (can be repeated for multiple organizations)").Strings()
	requestTimeout := flags.Flag("snyk.timeout", "Timeout for requests against Snyk API").Default("10").Int()
	listenAddress := flags.Flag("web.listen-address", "Address on which to expose metrics.").Default(":9532").String()
	log.AddFlags(flags)
	flags.HelpFlag.Short('h')
	flags.Version(version)
	kingpin.MustParse(flags.Parse(os.Args[1:]))

	if len(*snykOrganizations) != 0 {
		log.Infof("Starting Snyk exporter for organization '%s'", strings.Join(*snykOrganizations, ","))
	} else {
		log.Info("Starting Snyk exporter for all organization for token")
	}

	prometheus.MustRegister(vulnerabilityGauge)
	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "true")
	})

	done := make(chan error, 1)
	go func() {
		log.Infof("Listening on %s", *listenAddress)
		err := http.ListenAndServe(*listenAddress, nil)
		if err != nil {
			done <- err
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigs:
			done <- fmt.Errorf("received os signal '%s'", sig)
		}
	}()

	go runAPIPolling(done, *snykAPIURL, *snykAPIToken, *snykOrganizations, secondDuration(*snykInterval), secondDuration(*requestTimeout))

	reason := <-done
	if reason != nil {
		log.Errorf("Snyk exporter exited due to error: %v", reason)
		return
	}
	log.Infof("Snyk exporter exited with exit 0")
}

func secondDuration(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

func runAPIPolling(done chan error, url, token string, organizationIDs []string, requestInterval, requestTimeout time.Duration) {
	client := client{
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
		token:   token,
		baseURL: url,
	}
	organizations, err := getOrganizations(&client, organizationIDs)
	if err != nil {
		done <- err
		return
	}
	log.Infof("Running Snyk API scraper for organizations: %v", strings.Join(organizationNames(organizations), ", "))
	for {
		for _, organization := range organizations {
			log.Debugf("Collecting for organization '%s'", organization.Name)
			err := collect(&client, organization)
			if err != nil {
				done <- err
				return
			}
		}
		time.Sleep(requestInterval)
	}
}

func organizationNames(orgs []org) []string {
	var names []string
	for _, org := range orgs {
		names = append(names, org.Name)
	}
	return names
}

func getOrganizations(client *client, organizationIDs []string) ([]org, error) {
	orgsResponse, err := client.getOrganizations()
	if err != nil {
		return nil, err
	}
	organizations := orgsResponse.Orgs
	if len(organizationIDs) != 0 {
		organizations = filterByIDs(orgsResponse.Orgs, organizationIDs)
		if len(organizations) == 0 {
			return nil, fmt.Errorf("no organizations match the filter: '%v'", strings.Join(organizationIDs, ","))
		}
	}
	return organizations, nil
}

func filterByIDs(organizations []org, ids []string) []org {
	var filtered []org
	for i := range organizations {
		for _, id := range ids {
			if organizations[i].ID == id {
				filtered = append(filtered, organizations[i])
			}
		}
	}
	return filtered
}

func collect(client *client, organization org) error {
	projects, err := client.getProjects(organization.ID)
	if err != nil {
		return err
	}

	for _, project := range projects.Projects {
		start := time.Now()
		issues, err := client.getIssues(organization.ID, project.ID)
		if err != nil {
			log.Errorf("Failed to get issues for organization %s (%s) and project %s (%s): %v", organization.Name, organization.ID, project.Name, project.ID, err)
			continue
		}
		results := aggregateVulnerabilities(issues.Issues)
		setGauge(organization.Name, project.Name, results)
		duration := time.Since(start)
		log.Debugf("Collected data in %v for %s %s", duration, project.ID, project.Name)
	}
	return nil
}

func setGauge(organization, project string, results []aggregateResult) {
	for _, result := range results {
		vulnerabilityGauge.WithLabelValues(organization, project, result.title, result.severity).Set(float64(result.count))
	}
}

type aggregateResult struct {
	title    string
	severity string
	count    int
}

func aggregationKey(vulnerability vulnerability) string {
	return fmt.Sprintf("%s_%s", vulnerability.Severity, vulnerability.Title)
}
func aggregateVulnerabilities(issues issues) []aggregateResult {
	aggregateResults := make(map[string]aggregateResult)
	// dedupe vulnerabilities - the snyk API reports vulnerabilities as
	// separate if they are introduced via different top-level packages.
	// we remove duplicate occurrences by comparing the ID.
	vulnerabilities := dedupeVulnerabilities(issues.Vulnerabilities)
	for _, vulnerability := range vulnerabilities {
		aggregate, ok := aggregateResults[aggregationKey(vulnerability)]
		if !ok {
			aggregate = aggregateResult{
				title:    vulnerability.Title,
				severity: vulnerability.Severity,
				count:    0,
			}
		}
		aggregate.count++
		aggregateResults[aggregationKey(vulnerability)] = aggregate
	}
	var output []aggregateResult
	for i := range aggregateResults {
		output = append(output, aggregateResults[i])
	}
	return output
}

func dedupeVulnerabilities(vulnerabilities []vulnerability) []vulnerability {
	deduped := make(map[string]vulnerability)
	for i := range vulnerabilities {
		deduped[vulnerabilities[i].ID] = vulnerabilities[i]
	}
	var dedupedSlice []vulnerability
	for _, vulnerability := range deduped {
		dedupedSlice = append(dedupedSlice, vulnerability)
	}
	return dedupedSlice
}
