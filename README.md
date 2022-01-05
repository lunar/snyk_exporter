# Snyk exporter

[![Build Status](https://travis-ci.com/lunarway/snyk_exporter.svg?branch=master)](https://travis-ci.com/lunarway/snyk_exporter)
[![Go Report Card](https://goreportcard.com/badge/github.com/lunarway/snyk_exporter)](https://goreportcard.com/report/github.com/lunarway/snyk_exporter)
[![Docker Repository on Quay](https://quay.io/repository/lunarway/snyk_exporter/status "Docker Repository on Quay")](https://quay.io/repository/lunarway/snyk_exporter)

Prometheus exporter for [Snyk](https://snyk.io/) written in Go.
Allows for exporting scanning data into Prometheus by scraping the Snyk HTTP API.

# Installation

Several pre-compiled binaries are available from the [releases page](https://github.com/lunarway/snyk_exporter/releases).

A docker image is also available on our Quay.io registry.

```bash
docker run quay.io/lunarway/snyk_exporter --snyk.api-token <api-token>
```

# Usage

You need a Snyk API token to access to API.
Get your through the [Snyk account settings](https://app.snyk.io/account/).

It exposes prometheus metrics on `/metrics` on port `9532` (can be configured).

```bash
snyk_exporter --snyk.api-token <api-token>
```

See all configuration options with the `--help` flag

```bash
$ snyk_exporter --help
usage: snyk_exporter --snyk.api-token=SNYK.API-TOKEN [<flags>]

Snyk exporter for Prometheus. Provide your Snyk API token and the organization(s) to scrape to expose Prometheus metrics.

Flags:
  -h, --help               Show context-sensitive help (also try --help-long and --help-man).
      --snyk.api-url="https://snyk.io/api/v1"
                           Snyk API URL
      --snyk.api-token=SNYK.API-TOKEN
                           Snyk API token
  -i, --snyk.interval=600  Polling interval for requesting data from Snyk API in seconds
      --snyk.organization=SNYK.ORGANIZATION ...
                           Snyk organization ID to scrape projects from (can be repeated for multiple organizations)
      --snyk.timeout=10    Timeout for requests against Snyk API
      --web.listen-address=":9532"
                           Address on which to expose metrics.
      --log.level="info"   Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]
      --log.format="logger:stderr"
                           Set the log target and format. Example: "logger:syslog?appname=bob&local=7" or "logger:stdout?json=true"
      --version            Show application version.

```

It is possible to use a file to pass arguments to the exporter.
For example:

```bash
 echo --snyk.api-token=<>\n > args
```
And run the exporter using:

```bash
./snyk-exporter @args
```

# Design

The exporter starts a long-running go routine on startup that scrapes the Snyk API with a fixed interval (default every `10` minutes).
The interval can be configured as needed.

The API results are aggregated and recorded on the `snyk_vulnerabiilities_total` metric with the following labels:

- `organization` - The organization where the vulnerable project exists
- `project` - The project with a vulnerability
- `severity` - The severity of the vulnerability, can be `high`, `medium` and `low`
- `issue_type` - The type of issue, e.g. `vuln`, `license`
- `issue_title` - The issue title of the vulnerability, e.g. `Denial os Service (DoS)`. Can be the CVE if the vulnerability is not named by Snyk
- `ignored` - The issue is ignored in Snyk.
- `upgradeable` - The issue can be fixed by upgrading to a later version of the dependency.
- `patchable` - The issue is patchable through Snyk.
- `monitored` - The project is actively monitored by Snyk.

Here is an example.

```
snyk_vulnerabilities_total{organization="my-org",project="my-app",severity="high",issue_type="vuln",issue_title="Privilege Escalation",ignored="false",upgradeable="false",patchable="false",monitored="true"} 1.0
snyk_vulnerabilities_total{organization="my-org",project="my-app",severity="low",issue_type="vuln",issue_title="Sandbox (chroot) Escape",ignored="true",upgradeable="false",patchable="false",monitored="false"} 2.0
snyk_vulnerabilities_total{organization="my-org",project="my-app",severity="medium",issue_type="license",issue_title="MPL-2.0 license",ignored="true",upgradeable="false",patchable="false",monitored="true"} 1
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

```bash
$ docker run \
    -p9532:9532 \
    --snyk.api-token <api-token> \
    snyk_exporter

time="2019-01-11T09:42:34Z" level=info msg="Starting Snyk exporter for all organization for token" source="main.go:55"
time="2019-01-11T09:42:34Z" level=info msg="Listening on :9532" source="main.go:63"
time="2019-01-11T09:42:35Z" level=info msg="Running Snyk API scraper for organizations: <omitted>" source="main.go:106"
```

# Deployment

## Simple Kubernetes deployment

To deploy the exporter in Kubernetes, you can find a simple Kubernetes deployment and secret yaml in the `deployments/kubernetes/snyk-exporter` folder.  
You have to add your snyk token and the snyk organization in the `secrets.yaml`.  
You can configure the arguments in args section of the `deployment.yaml`.  
The deployment will be applied on your current namespace.

To deploy it to your kubernetes cluster run the following commands:

```bash
kubectl apply -f deployments/kubernetes/snyk-exporter/secrets.yaml
kubectl apply -f deployments/kubernetes/snyk-exporter/deployment.yaml
kubectl apply -f deployments/kubernetes/snyk-exporter/service.yaml
```

## Helm chart

The helm chart placed in `deployments/helm/charts/snyk-exporter` folder. The configuration guide added to the `values.yaml`.  
Please apply your config separately and override it in Helm relese.  
The Helm deployment will be applied on your current namespace.


Sample `myvalues.yaml`

```yaml
config:
  snyk:
    apiToken: <your Snyk service API token place as clear text >
    organization: <Your Snyk organization ID place as clear text>

service:
  type: ClusterIP
  port: 9532
```

Dry-run and debug helm chart (recommend before run the install command)

```bash
helm install \
  -f ~/myvalues.yaml \
  snyk-exporter \
  deployments/helm/charts/snyk-exporter/ \
  --dry-run \
  --debug
```

Install helm chart

```bash
helm install \
  -f ~/myvalues.yaml \
  snyk-exporter \
  deployments/helm/charts/snyk-exporter/
```

## Prometheus scrape configuration

Please do not forget to replace a text with your namespace name.

```yaml
- job_name: snyk-exporter
  scrape_interval: 30s
  scrape_timeout: 3s
  metrics_path: /metrics
  scheme: http
  static_configs:
    - targets:
        - snyk-exporter.<your namespace name>:9532
```

## Kubernetes deployment with all organization

To deploy the exporter in Kubernetes, you can find a simple Kubernetes `deployment.yaml` and `secret yaml` in the `examples` folder. You have to add your **snyk token** in the `secrets.yaml` and/or the **snyk organizations** that you want to get metrics from in the args section of the `deployment.yaml`. If you don't specify a `snyk-organization`, the exporter will scrape all organizations the token provides access to. The example assumes that you have a namespace in kubernetes named: monitoring.

It further assumes that you have [kubernetes service discovery](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#kubernetes_sd_config) configured for you Prometheus instance and a target that will gather metrics from pods, similar to this:

```yaml
- job_name: 'kubernetes-pods'
  kubernetes_sd_configs:
  - role: pod

  relabel_configs:
  - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
    action: keep
    regex: true
  - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
    action: replace
    target_label: __metrics_path__
    regex: (.+)
  - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
    action: replace
    regex: (.+):(?:\d+);(\d+)
    replacement: ${1}:${2}
    target_label: __address__
  - action: labelmap
    regex: __meta_kubernetes_pod_label_(.+)
```

The exporter expose http endpoints that can be used by kubernetes probes:
* `/healthz` - used for liveness probe, always returns `healthy`, status code 200.
* `/ready` - used for readiness probe, return `true` and status code 200 after the first scrape completed. Otherwise, it returns `false`, with status code 503.

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
