{{/*
Expand the name of the chart.
*/}}
{{- define "snyk-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "snyk-exporter.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "snyk-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "snyk-exporter.labels" -}}
helm.sh/chart: {{ include "snyk-exporter.chart" . }}
{{ include "snyk-exporter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "snyk-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "snyk-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "snyk-exporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "snyk-exporter.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the args for the image
*/ -}}
{{- define "snyk-exporter.args" -}}
{{- if .Values.config }}
{{- if .Values.config.snyk }}
{{- if .Values.config.snyk.apiToken }}
{{- print "- " ((list "--snyk.api-token" .Values.config.snyk.apiToken | join "=") | quote) "\n" }}
{{- end }}
{{- if .Values.config.snyk.organization }}
{{- print "- " ((list "--snyk.organization" .Values.config.snyk.organization | join "=") | quote) "\n"  }}
{{- end }}
{{- if .Values.config.snyk.apiUrl }}
{{- print "- " ((list "--snyk.api-url" .Values.config.snyk.apiUrl | join "=") | quote) "\n"  }}
{{- end }}
{{- if .Values.config.snyk.interval }}
{{- print "- " ((list "--snyk.interval" .Values.config.snyk.interval | join "=") | quote) "\n" }}
{{- end }}
{{- if .Values.config.snyk.timeout }}
{{- print "- " ((list "--snyk.timeout" .Values.config.snyk.timeout | join "=") | quote) "\n" }}
{{- end }}
{{- end }}
{{- if .Values.config.web }}
{{- if .Values.config.web.listenAddress }}
{{- print "- " ((list "--web.listen-address" .Values.config.web.listenAddress | join "=") | quote) "\n" }}
{{- end }}
{{- end }}
{{- if .Values.config.log }}
{{- if .Values.config.log.level }}
{{- print "- " ((list "--log.level" .Values.config.log.level | join "=") | quote) "\n" }}
{{- end }}
{{- if .Values.config.log.format }}
{{- print "- " ((list "--log.format" .Values.config.log.format | join "=") | quote) "\n" }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Define envs for the image
*/ -}}
{{- define "snyk-exporter.secrets" -}}
{{- if .Values.config -}}
{{- if .Values.config.snyk -}}
{{- if .Values.config.snyk.apiToken -}}
snyk.api-token: {{ .Values.config.snyk.apiToken | quote }}
{{- end }}
{{- if .Values.config.snyk.organization }}
snyk.organization: {{ .Values.config.snyk.organization | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create env. variables definition.
*/}}
{{- define "snyk-exporter.envVars" -}}
{{- $snykExporterEnvVars := dict -}}
{{- $snykSecretName := (include "snyk-exporter.fullname" $) -}}
{{- if .Values.config }}
{{- if .Values.config.snyk }}
{{- if .Values.config.snyk.apiToken }}
{{- $_ := set $snykExporterEnvVars "snyk.api-token" .Values.config.snyk.apiToken }}
{{- end }}
{{- if .Values.config.snyk.organization }}
{{- $_ := set $snykExporterEnvVars "snyk.organization" .Values.config.snyk.organization }}
{{- end }}
{{- end }}
{{- end }}
{{- range $key, $val := $snykExporterEnvVars }}
- name: {{ $key | replace "." "_" | replace "-" "_" | upper }}
  valueFrom:
    secretKeyRef:
      name: {{ $snykSecretName }}
      key: {{ $key }}
{{- end }}
{{- end }}
