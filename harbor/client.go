package harbor

type Client interface {
	GetArtifacts(project, repository string) ([]*Artifact, error)
	GetArtifactVulnerabilities(project, repository, artifact string) ([]*Vulnerability, error)
}

type client struct {
  harborConfig *HarborConfig
}

func NewClient() Client {
	return &client{}
}

func (c *client) GetArtifacts(project, repository string) ([]*Artifact, error) {
	uri := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts", l.config.HarborHost, eventData.Repository.Namespace, eventData.Repository.Name)
	resp, err := http.Get(uri)
	if err != nil {
		log.Error("Error finding Tag for image", zap.String("image", eventData.Repository.RepoFullName), zap.Error(err))
		return nil, err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	artifacts := []*harbor.Artifact{}
	json.Unmarshal(body, &artifacts)

	return artifacts, nil
}

func (c *client) GetArtifactVulnerabilities(project, repository, artifact string) ([]*Vulnerability, error) {
	uri = fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", l.config.HarborHost, eventData.Repository.Namespace, eventData.Repository.Name, artifacts[0].Tags[0].Name)
	resp, err = http.Get(uri)
	if err != nil {
		log.Error("error reading Vulnerabilities report from Harbor", zap.Error(err))
		return nil, err
	}

	body, _ = ioutil.ReadAll(resp.Body)
	scanOverview := &harbor.ScanOverview{}
	json.Unmarshal(body, scanOverview)

	return body, nil
}
