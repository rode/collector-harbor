package harbor

// Event received
type Event struct {
  EventType    string   `json:"event_type"`
  Project      string   `json:"project"`
  RepoName     string   `json:"repo_name"`
  Tag          string   `json:"tag"`
  FullName     string   `json:"full_name"`
  TriggerTime  string   `json:"trigger_time"`
  ImageId      string   `json:"image_id"`
  ProjectType  string   `json:"project_type"`
	Vulnerability *Vulnerability `json:"vulnerability"`
}

// Vulnerability is...
type Vulnerability struct {
	Conditions []*Condition `json:"conditions"`
	Name       string       `json:"name"`
	Status     string       `json:"status"`
}

// Condition is...
type Condition struct {
	ErrorThreshold  string `json:"errorThreshold"`
	Metric          string `json:"metric"`
	OnLeakPeriod    bool   `json:"onLeakPeriod"`
	Operator        string `json:"operator"`
	Status          string `json:"status"`
}
