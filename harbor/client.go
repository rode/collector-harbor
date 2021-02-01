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

type Client interface {
	GetArtifacts(project, repository string) ([]*Artifact, error)
	GetArtifactReport(project, repository, tag string) (*Report, error)
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

func (c *client) GetArtifactReport(project, repository, tag string) (*Report, error) {
	var scanOverview ScanOverview

	uri := fmt.Sprintf("/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", project, repository, tag)

	err := c.get(uri, &scanOverview)
	if err != nil {
		return nil, err
	}

	return scanOverview.Report, nil
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
