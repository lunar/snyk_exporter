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
	typeLabel         = "type"
	severityLabel     = "severity"
	organizationLabel = "organization"
)

var (
	vulnerabilityGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "snyk_vulnerabilities_total",
			Help: "Gauge of Snyk vulnerabilities",
		},
		[]string{organizationLabel, projectLabel, typeLabel, severityLabel},
	)
)

func main() {
	flags := kingpin.New("snyk_exporter", "Snyk exporter for Prometheus. Provide your Snyk API token and the organization(s) to scrape to expose Prometheus metrics.")
	snykAPIURL := flags.Flag("snyk.api-url", "Snyk API URL").Default("https://snyk.io/api/v1").String()
	snykAPIToken := flags.Flag("snyk.api-token", "Snyk API token").Required().String()
	snykInterval := flags.Flag("snyk.interval", "Polling interval for requesting data from Snyk API in seconds").Short('i').Default("60").Int()
	snykOrganizations := flags.Flag("snyk.organization", "Snyk organization to scrape projects from (can be repeated for multiple organizations)").Required().Strings()
	requestTimeout := flags.Flag("snyk.timeout", "Timeout for requests against Snyk API").Default("10").Int()
	listenAddress := flags.Flag("web.listen-address", "Address on which to expose metrics.").Default(":9532").String()
	log.AddFlags(kingpin.CommandLine)
	flags.HelpFlag.Short('h')
	kingpin.MustParse(flags.Parse(os.Args[1:]))

	log.Infof("Starting Snyk exporter for organization '%s'", strings.Join(*snykOrganizations, ","))

	prometheus.MustRegister(vulnerabilityGauge)
	http.Handle("/metrics", promhttp.Handler())

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

func runAPIPolling(done chan error, url, token string, organizations []string, requestInterval, requestTimeout time.Duration) {
	log.Info("Running Snyk API scraper...")
	client := client{
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
		token:   token,
		baseURL: url,
	}
	for {
		for _, organization := range organizations {
			log.Debugf("Collecting for organization '%s'", organization)
			err := collect(&client, organization)
			if err != nil {
				done <- err
				return
			}
		}
		time.Sleep(requestInterval)
	}
}

func collect(client *client, organization string) error {
	projects, err := client.getProjects(organization)
	if err != nil {
		return err
	}
	organizationID := projects.Org.ID

	for _, project := range projects.Projects {
		issues, err := client.getIssues(organizationID, project.ID)
		if err != nil {
			log.Errorf("Failed to get issues for organization %s (%s) and project %s (%s): %v", organization, organizationID, project.Name, project.ID, err)
			continue
		}
		results := aggregateVulnerabilities(issues.Issues)
		setGauge(organization, project.Name, results)
		log.Debugf("Collected data for %s %s", project.ID, project.Name)
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
