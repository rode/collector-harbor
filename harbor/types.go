package harbor

// Event received
type Event struct {
	Type      string     `json:"type"`
	OccurAt   int        `json:"occur_at"`
	Operator  string     `json:"operator"`
	EventData *EventData `json:"event_data"`
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
	Digest              string `json:"digest"`
	Tag                 string `json:"tag"`
	ResourceUrl         string `json:"resource_url"`
  ScanOverview *ScanOverview `json:"scan_overview"`
}

// ScanOverview is...
type ScanOverview struct {
  Report *Report `json:"application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"`
}

// is...
type Report struct {
  ReportId            string `json:"report_id"`
  ScanStatus          string `json:"scan_status"`
  Severity            string `json:"severity"`
  Duration            int    `json:"duration"`
  Summary           *Summary `json:"summary"`
  StartTime           string `json:"start_time"`
  EndTime             string `json:"end_time"`
  Scanner           *Scanner `json:"scanner"`
  CompletePercentage  int    `json:"complete_percent"`
  Vulnerabilities   *[]Vulnerability `json:"vulnerabilities"`
}
// Summary is...
type Vulnerability  struct {
  ArtifactDigest  string `json:"artifact_digest"`
  Description     string `json:"description"`
  FixVersion      string `json:"fix_version"`
  ID              string `json:"id"`
  Links         []string `json:"links"`
  Package         string `json:"package"`
  Severity        string `json:"severity"`
  Version         string `json:"version"`
}

// Summary is...
type Summary struct {
  Total      int `json:"total"`
  Fixable    int `json:"fixable"`
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
