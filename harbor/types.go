package harbor

// Event received
type Event struct {
  Type         string   `json:"type"`
  OccurAt      int      `json:"occur_at"`
  Operator     string   `json:"operator"`
  EventData *EventData  `json:"event_data"`
}

// Vulnerability is...
type EventData struct {
	Resources []*Resource  `json:"resources"`
  Repository *Repository `json:"repository"`
}

// Resource is...
type Resource struct {
  Digest        string `json:"digest"`
  Tag           string `json:"tag"`
  ResourceUrl   string `json:"resource_url"`
}

// Repository is...
type Repository struct {
  DateCreated   int    `json:"date_created"`
  Name          string `json:"name"`
  Namespace     string `json:"namespace"`
  RepoFullName  string `json:"repo_full_name"`
  RepoType      string `json:"repo_type"`
}
