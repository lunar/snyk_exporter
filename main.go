package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
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

		if ready == true {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		w.Write([]byte(strconv.FormatBool(ready)))
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
			log.Infof("Received os signal '%s'. Terminating...", sig)
			done <- nil
		}
	}()

	go runAPIPolling(done, *snykAPIURL, *snykAPIToken, *snykOrganizations, secondDuration(*snykInterval), secondDuration(*requestTimeout))

	reason := <-done
	if reason != nil {
		log.Errorf("Snyk exporter exited due to error: %v", reason)
		os.Exit(1)
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
		var gaugeResults []gaugeResult
		for _, organization := range organizations {
			log.Debugf("Collecting for organization '%s'", organization.Name)
			var results []gaugeResult
			err := poll(organization, func(organization org) error {
				var err error
				results, err = collect(&client, organization)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				done <- err
				return
			}
			gaugeResults = append(gaugeResults, results...)
		}
		scrapeMutex.Lock()
		register(gaugeResults)
		scrapeMutex.Unlock()
		readyMutex.Lock()
		ready = true
		readyMutex.Unlock()
		time.Sleep(requestInterval)
	}
}

// poll polles the collector for new data. In case of errors it decides whether
// to keep on polling or stop b y returning an error.
func poll(organization org, collector func(org) error) error {
	err := collector(organization)
	if err != nil {
		httpErr, ok := err.(*url.Error)
		if ok {
			if httpErr.Timeout() {
				log.Errorf("Collection failed for organization '%s' due timeout", organization.Name)
				return nil
			}
			if httpErr.Err == io.ErrUnexpectedEOF {
				log.Errorf("Collection failed for organization '%s' due to unexpected EOF", organization.Name)
				return nil
			}
		}
		if err == io.ErrUnexpectedEOF {
			log.Errorf("Collection failed for organization '%s' due to unexpected EOF", organization.Name)
			return nil
		}
		return err
	}
	return nil
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

func collect(client *client, organization org) ([]gaugeResult, error) {
	projects, err := client.getProjects(organization.ID)
	if err != nil {
		return nil, err
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
