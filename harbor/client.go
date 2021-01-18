package harbor

import (
	"fmt"
	"encoding/json"
	"net/http"
	"io/ioutil"

	"go.uber.org/zap"
	"github.com/rode/collector-harbor/config"
)

type Client interface {
	GetArtifacts(log *zap.Logger, project, repository string, eventData *EventData) ([]*Artifact, error)
	GetArtifactVulnerabilities(log *zap.Logger, project, repository, artifacts []*Artifact, eventData *EventData) ([]byte, error)
}

type client struct {
  HarborConfig *config.HarborConfig
}

func NewClient() Client {
	return &client{}
}

func (c *client) GetArtifacts(log *zap.Logger, project, repository string, eventData *EventData) ([]*Artifact, error) {
	uri := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts", c.HarborConfig.Host, eventData.Repository.Namespace, eventData.Repository.Name)
	resp, err := http.Get(uri)
	if err != nil {
		log.Error("Error finding Tag for image", zap.String("image", eventData.Repository.RepoFullName), zap.Error(err))
		return nil, err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	artifacts := []*Artifact{}
	json.Unmarshal(body, &artifacts)

	return artifacts, nil
}

func (c *client) GetArtifactVulnerabilities(log *zap.Logger, project, repository, artifacts []*Artifact, eventData *EventData) ([]byte, error) {
  uri := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", c.HarborConfig.Host, eventData.Repository.Namespace, eventData.Repository.Name, artifacts[0].Tags[0].Name)
  resp, err := http.Get(uri)
	if err != nil {
		log.Error("error reading Vulnerabilities report from Harbor", zap.Error(err))
		return nil, err
	}

  body, _ := ioutil.ReadAll(resp.Body)
	scanOverview := &ScanOverview{}
	json.Unmarshal(body, scanOverview)

	return body, nil
}
