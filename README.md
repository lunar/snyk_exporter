# Snyk exporter

[![Build Status](https://travis-ci.org/lunarway/snyk_exporter.svg?branch=master)](https://travis-ci.org/lunarway/snyk_exporter)
[![Go Report Card](https://goreportcard.com/badge/github.com/lunarway/snyk_exporter)](https://goreportcard.com/report/github.com/lunarway/snyk_exporter)

Prometheus exporter for [Snyk](https://snyk.io/) written in Go.
Allows for exporting scanning data into Prometheus by scraping the Snyk HTTP API.

# Usage

You need a Snyk API token to access to API.
Get your through the [Snyk account settings](https://app.snyk.io/account/).

It exposes prometheus metrics on `/metrics` on port `9532` (can be configured).

```
snyk_exporter --snyk.api-token <api-token> --snyk.organization nasa
```

See all configuration options with the `--help` flag

```
$ snyk_exporter --help
usage: snyk_exporter --snyk.api-token=SNYK.API-TOKEN --snyk.organization=SNYK.ORGANIZATION [<flags>]

Snyk exporter for Prometheus. Provide your Snyk API token and the organization(s) to scrape to expose Prometheus metrics.

Flags:
  -h, --help              Show context-sensitive help (also try --help-long and --help-man).
      --snyk.api-url="https://snyk.io/api/v1"
                          Snyk API URL
      --snyk.api-token=SNYK.API-TOKEN
                          Snyk API token
  -i, --snyk.interval=60  Polling interval for requesting data from Snyk API in seconds
      --snyk.organization=SNYK.ORGANIZATION ...
                          Snyk organization to scrape projects from (can be repeated for multiple organizations)
      --snyk.timeout=10   Timeout for requests against Snyk API
      --web.listen-address=":9532"
                          Address on which to expose metrics.
```

# Design

The exporter starts a long-running go routine on startup that scrapes the Snyk API with a fixed interval (default every `60` seconds).
The interval can be configured as needed.

The API results are aggregated and recorded on the `snyk_vulnerabiilities_total` metric with the following labels:

- `organization` - The organization where the vulnerable project exists
- `project` - The project with a vulnerability
- `severity` - The severity of the vulnerability, can be `high`, `medium` and `low`
- `type` - The type of the vulnerability, e.g. `Denial os Service (DoS)`. Can be the CVE if the vulnerability is not named by Snyk

Here is an example.

```
snyk_vulnerabilities_total{organization="my-org",project="my-app",severity="high",type="Privilege Escalation"} 1.0
snyk_vulnerabilities_total{organization="my-org",project="my-app",severity="low",type="Sandbox (chroot) Escape"} 2.0
```

# Build

The exporter can be build using the standard Go tool chain if you have it available.

```
go build
```

You can build inside a docker imagee as well.
This produces a `snyk_exporter` image that can run with the binary as entry point.

```
docker build -t snyk_exporter .
```

This is useful if the exporter is to be depoyled in Kubernetes or other dockerized environments.

Here is an example of running the exporter locally.

```
$ docker run -p9532:9532 snyk_exporter --snyk.api-token <api-token>
time="2019-01-10T19:57:00Z" level=info msg="Starting Snyk exporter for organization 'squad-nasa'" source="main.go:53"
time="2019-01-10T19:57:01Z" level=info msg="Listening on :9532" source="main.go:63"
time="2019-01-10T19:57:01Z" level=info msg="Running Snyk API scraper..." source="main.go:94"
```

# Development

The project uses Go modules so you need Go version >=1.11 to run it.
Run builds and tests with the standard Go tool chain.

```go
go build
go test
```

# Credits
This exporter is written with inspiration from [dnanexus/prometheus_snyk_exporter](https://github.com/dnanexus/prometheus_snyk_exporter).

Main difference is the aggregations are done by Prometheus instead of in the exporter.
It also scrapes the Snyk API asyncronously, ie. not when Prometheus tries to scrape the metrics.
