package harbor

type Client interface {
	GetArtifacts(project, repository string) ([]*Artifact, error)
	GetArtifactVulnerabilities(project, repository, artifact string) ([]*Vulnerability, error)
}

type client struct {
}

func NewClient() Client {
	return &client{}
}

func (c *client) GetArtifacts(project, repository string) ([]*Artifact, error) {
	return nil, nil
}

func (c *client) GetArtifactVulnerabilities(project, repository, artifact string) ([]*Vulnerability, error) {
	return nil, nil
}
