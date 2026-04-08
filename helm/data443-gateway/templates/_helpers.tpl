{{/*
Expand the name of the chart.
*/}}
{{- define "data443-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "data443-gateway.fullname" -}}
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
Chart label.
*/}}
{{- define "data443-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "data443-gateway.labels" -}}
helm.sh/chart: {{ include "data443-gateway.chart" . }}
{{ include "data443-gateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "data443-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "data443-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "data443-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "data443-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL host — sub-chart or external.
*/}}
{{- define "data443-gateway.pgHost" -}}
{{- if .Values.externalPostgresql.enabled }}
{{- .Values.externalPostgresql.host }}
{{- else }}
{{- printf "%s-postgresql" (include "data443-gateway.fullname" .) }}
{{- end }}
{{- end }}

{{/*
PostgreSQL port.
*/}}
{{- define "data443-gateway.pgPort" -}}
{{- if .Values.externalPostgresql.enabled }}
{{- .Values.externalPostgresql.port | toString }}
{{- else }}
{{- "5432" }}
{{- end }}
{{- end }}

{{/*
PostgreSQL database.
*/}}
{{- define "data443-gateway.pgDatabase" -}}
{{- if .Values.externalPostgresql.enabled }}
{{- .Values.externalPostgresql.database }}
{{- else }}
{{- .Values.postgresql.auth.database }}
{{- end }}
{{- end }}

{{/*
PostgreSQL username.
*/}}
{{- define "data443-gateway.pgUser" -}}
{{- if .Values.externalPostgresql.enabled }}
{{- .Values.externalPostgresql.username }}
{{- else }}
{{- .Values.postgresql.auth.username }}
{{- end }}
{{- end }}

{{/*
Redis host — sub-chart or external.
*/}}
{{- define "data443-gateway.redisHost" -}}
{{- if .Values.externalRedis.enabled }}
{{- .Values.externalRedis.host }}
{{- else }}
{{- printf "%s-redis-master" (include "data443-gateway.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Redis port.
*/}}
{{- define "data443-gateway.redisPort" -}}
{{- if .Values.externalRedis.enabled }}
{{- .Values.externalRedis.port | toString }}
{{- else }}
{{- "6379" }}
{{- end }}
{{- end }}
