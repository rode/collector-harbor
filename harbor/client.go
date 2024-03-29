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

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/rode/collector-harbor/config"
	"io/ioutil"
	"net/http"
	"time"
)

//go:generate counterfeiter -generate

//counterfeiter:generate . Client
type Client interface {
	GetProjectByName(projectName string) (*Project, error)
	GetArtifacts(project, repository string) ([]*Artifact, error)
	GetArtifactReport(project, repository, artifactRef string) (*Report, error)
	GetArtifactUrl(projectName, repository, artifactRef string) (string, error)
}

type client struct {
	harborConfig   *config.HarborConfig
	basicAuthToken string
	httpClient     *http.Client
}

func NewClient(harborConfig *config.HarborConfig) Client {
	c := &client{
		harborConfig: harborConfig,
		httpClient: &http.Client{
			Timeout: time.Second * 10,
		},
	}

	if harborConfig.Insecure {
		c.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: harborConfig.Insecure,
			},
			Proxy: http.ProxyFromEnvironment,
		}
	}

	if harborConfig.Username != "" && harborConfig.Password != "" {
		c.basicAuthToken = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", harborConfig.Username, harborConfig.Password)))
	}

	return c
}

func (c *client) GetArtifacts(project, repository string) ([]*Artifact, error) {
	var artifacts []*Artifact

	uri := fmt.Sprintf("/api/v2.0/projects/%s/repositories/%s/artifacts", project, repository)

	err := c.get(uri, &artifacts)
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (c *client) GetArtifactReport(project, repository, artifactRef string) (*Report, error) {
	var scanOverview ScanOverview

	uri := fmt.Sprintf("/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", project, repository, artifactRef)

	err := c.get(uri, &scanOverview)
	if err != nil {
		return nil, err
	}

	return scanOverview.Report, nil
}

func (c *client) GetProjectByName(name string) (*Project, error) {
	var projects []*Project

	uri := fmt.Sprintf("/api/v2.0/projects?name=%s", name)

	err := c.get(uri, &projects)
	if err != nil {
		return nil, err
	}

	for _, project := range projects {
		if project.Name == name {
			return project, nil
		}
	}

	return nil, fmt.Errorf("project with name %s not found", name)
}

func (c *client) GetArtifactUrl(projectName, repository, artifactRef string) (string, error) {
	project, err := c.GetProjectByName(projectName)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/harbor/projects/%d/repositories/%s/artifacts/%s", c.harborConfig.Host, project.Id, repository, artifactRef), nil
}

func (c *client) get(uri string, resource interface{}) error {
	req, err := http.NewRequest(http.MethodGet, c.harborConfig.Host+uri, nil)
	if err != nil {
		return err
	}

	if c.basicAuthToken != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", c.basicAuthToken))
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, resource)
}
