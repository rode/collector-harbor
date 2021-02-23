// Copyright 2021 The Rode Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package harbor

// Event received
type Event struct {
	Type     WebhookEvent `json:"type"`
	OccurAt  int64        `json:"occur_at"`
	Operator string       `json:"operator"`
	Data     *EventData   `json:"event_data"`
}

// Vulnerability is...
type EventData struct {
	Resources  []*Resource `json:"resources"`
	Repository *Repository `json:"repository"`
}

// Repository is...
type Repository struct {
	DateCreated  int    `json:"date_created"`
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	RepoFullName string `json:"repo_full_name"`
	RepoType     string `json:"repo_type"`
}

// Resource is...
type Resource struct {
	Digest       string        `json:"digest"`
	Tag          string        `json:"tag"`
	ResourceUrl  string        `json:"resource_url"`
	ScanOverview *ScanOverview `json:"scan_overview"`
}

// ScanOverview is...
type ScanOverview struct {
	Report *Report `json:"application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"`
}

// is...
type Report struct {
	ReportId           string           `json:"report_id"`
	ScanStatus         string           `json:"scan_status"`
	Severity           string           `json:"severity"`
	Duration           int              `json:"duration"`
	Summary            *Summary         `json:"summary"`
	StartTime          string           `json:"start_time"`
	EndTime            string           `json:"end_time"`
	Scanner            *Scanner         `json:"scanner"`
	CompletePercentage int              `json:"complete_percent"`
	Vulnerabilities    []*Vulnerability `json:"vulnerabilities"`
}

// Summary is...
type Vulnerability struct {
	ArtifactDigest string   `json:"artifact_digest"`
	Description    string   `json:"description"`
	FixVersion     string   `json:"fix_version"`
	ID             string   `json:"id"`
	Links          []string `json:"links"`
	Package        string   `json:"package"`
	Severity       string   `json:"severity"`
	Version        string   `json:"version"`
}

// Summary is...
type Summary struct {
	Total   int    `json:"total"`
	Fixable int    `json:"fixable"`
	Summary *Count `json:"summary"`
}

// Count is...
type Count struct {
	Critical int `json:"Critical"`
	High     int `json:"High"`
	Low      int `json:"Low"`
	Medium   int `json:"Medium"`
}

// Scanner is...
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Artifact struct {
	Tags   []*Tag `json:"tags"`
	Digest string `json:"digest"`
}

type Tag struct {
	Name string `json:"name"`
}

type WebhookEvent string

const (
	PUSH_ARTIFACT      WebhookEvent = "PUSH_ARTIFACT"
	SCANNING_FAILED    WebhookEvent = "SCANNING_FAILED"
	SCANNING_COMPLETED WebhookEvent = "SCANNING_COMPLETED"
)
