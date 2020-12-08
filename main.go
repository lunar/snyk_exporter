package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
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
	ignoredLabel      = "ignored"
	upgradeableLabel  = "upgradeable"
	patchableLabel    = "patchable"
)

var (
	vulnerabilityGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "snyk_vulnerabilities_total",
			Help: "Gauge of Snyk vulnerabilities",
		},
		[]string{organizationLabel, projectLabel, issueTitleLabel, severityLabel, ignoredLabel, upgradeableLabel, patchableLabel},
	)
)

var (
	ready       = false
	readyMutex  = &sync.RWMutex{}
	scrapeMutex = &sync.RWMutex{}
)

var (
	version = ""
)

func main() {
	flags := kingpin.New("snyk_exporter", "Snyk exporter for Prometheus. Provide your Snyk API token and the organization(s) to scrape to expose Prometheus metrics.")
	snykAPIURL := flags.Flag("snyk.api-url", "Snyk API URL").Default("https://snyk.io/api/v1").String()
	snykAPIToken := flags.Flag("snyk.api-token", "Snyk API token").Required().String()
	snykInterval := flags.Flag("snyk.interval", "Polling interval for requesting data from Snyk API in seconds").Short('i').Default("600").Int()
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
	http.Handle("/metrics", promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			scrapeMutex.RLock()
			defer scrapeMutex.RUnlock()
			promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}).ServeHTTP(rw, r)
		}),
	))

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "healthy")
	})

	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		readyMutex.RLock()
		defer readyMutex.RUnlock()

		if ready {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		_, err := w.Write([]byte(strconv.FormatBool(ready)))
		if err != nil {
			log.With("error", err).Errorf("Failed to write ready response: %v", err)
		}
	})

	// context used to stop worker components from signal or component failures
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	// used to report errors from components
	var exitCode int
	componentFailed := make(chan error, 1)
	var wg sync.WaitGroup

	go func() {
		log.Infof("Listening on %s", *listenAddress)
		err := http.ListenAndServe(*listenAddress, nil)
		if err != nil {
			componentFailed <- fmt.Errorf("http listener stopped: %v", err)
		}
	}()

	// Go routine responsible for starting shutdown sequence based of signals or
	// component failures
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case sig := <-sigs:
			log.Infof("Received os signal '%s'. Terminating...", sig)
		case err := <-componentFailed:
			if err != nil {
				log.Errorf("Component failed: %v", err)
				exitCode = 1
			}
		}
		stop()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("Snyk API scraper starting")
		defer log.Info("Snyk API scraper stopped")
		err := runAPIPolling(ctx, *snykAPIURL, *snykAPIToken, *snykOrganizations, secondDuration(*snykInterval), secondDuration(*requestTimeout))
		if err != nil {
			componentFailed <- fmt.Errorf("snyk api scraper: %w", err)
		}
	}()

	// wait for all components to stop
	wg.Wait()
	if exitCode != 0 {
		log.Errorf("Snyk exporter exited with exit %d", exitCode)
		os.Exit(exitCode)
	} else {
		log.Infof("Snyk exporter exited with exit 0")
	}
}

func secondDuration(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

func runAPIPolling(ctx context.Context, url, token string, organizationIDs []string, requestInterval, requestTimeout time.Duration) error {
	client := client{
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
		token:   token,
		baseURL: url,
	}
	organizations, err := getOrganizations(&client, organizationIDs)
	if err != nil {
		return err
	}
	log.Infof("Running Snyk API scraper for organizations: %v", strings.Join(organizationNames(organizations), ", "))

	// kick off a poll right away to get metrics available right after startup
	pollAPI(ctx, &client, organizations)

	ticker := time.NewTicker(requestInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			pollAPI(ctx, &client, organizations)
		}
	}
}

// pollAPI collects data from provided organizations and registers them in the
// prometheus registry.
func pollAPI(ctx context.Context, client *client, organizations []org) {
	var gaugeResults []gaugeResult
	for _, organization := range organizations {
		log.Infof("Collecting for organization '%s'", organization.Name)
		results, err := collect(ctx, client, organization)
		if err != nil {
			log.With("error", err).
				With("organzationName", organization.Name).
				With("organzationId", organization.ID).
				Errorf("Collection failed for organization '%s': %v", organization.Name, err)
			continue
		}
		log.Infof("Recorded %d results for organization '%s'", len(results), organization.Name)
		gaugeResults = append(gaugeResults, results...)
		// stop right away in case of the context being cancelled. This ensures that
		// we don't wait for a complete collect run for all organizations before
		// stopping.
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
	log.Infof("Exposing %d results as metrics", len(gaugeResults))
	scrapeMutex.Lock()
	register(gaugeResults)
	scrapeMutex.Unlock()
	readyMutex.Lock()
	ready = true
	readyMutex.Unlock()
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

// register registers results in the vulnerbility gauge. To handle changing
// flags, e.g. ignored, upgradeable the metric is cleared before setting new
// values.
// See https://github.com/lunarway/snyk_exporter/issues/21 for details.
func register(results []gaugeResult) {
	vulnerabilityGauge.Reset()
	for _, r := range results {
		for _, result := range r.results {
			vulnerabilityGauge.WithLabelValues(r.organization, r.project, result.title, result.severity, strconv.FormatBool(result.ignored), strconv.FormatBool(result.upgradeable), strconv.FormatBool(result.patchable)).Set(float64(result.count))
		}
	}
}

type gaugeResult struct {
	organization string
	project      string
	results      []aggregateResult
}

func collect(ctx context.Context, client *client, organization org) ([]gaugeResult, error) {
	projects, err := client.getProjects(organization.ID)
	if err != nil {
		return nil, fmt.Errorf("get projects for organization: %w", err)
	}

	var gaugeResults []gaugeResult
	for _, project := range projects.Projects {
		start := time.Now()
		issues, err := client.getIssues(organization.ID, project.ID)
		if err != nil {
			log.Errorf("Failed to get issues for organization %s (%s) and project %s (%s): %v", organization.Name, organization.ID, project.Name, project.ID, err)
			continue
		}
		results := aggregateVulnerabilities(issues.Issues)
		gaugeResults = append(gaugeResults, gaugeResult{
			organization: organization.Name,
			project:      project.Name,
			results:      results,
		})
		duration := time.Since(start)
		log.Debugf("Collected data in %v for %s %s", duration, project.ID, project.Name)
		// stop right away in case of the context being cancelled. This ensures that
		// we don't wait for a complete collect run for all projects before
		// stopping.
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}
	}
	return gaugeResults, nil
}

type aggregateResult struct {
	title       string
	severity    string
	ignored     bool
	upgradeable bool
	patchable   bool
	count       int
}

func aggregationKey(vulnerability vulnerability) string {
	return fmt.Sprintf("%s_%s_%t_%t_%t", vulnerability.Severity, vulnerability.Title, vulnerability.Ignored, vulnerability.Upgradeable, vulnerability.Patchable)
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
				title:       vulnerability.Title,
				severity:    vulnerability.Severity,
				count:       0,
				ignored:     vulnerability.Ignored,
				upgradeable: vulnerability.Upgradeable,
				patchable:   vulnerability.Patchable,
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
