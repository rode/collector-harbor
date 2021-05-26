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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/jarcoal/httpmock"
	. "github.com/onsi/gomega"
	"github.com/rode/collector-harbor/config"
	"net/http"
	"strings"
	"testing"
)

var fake = gofakeit.New(0)

func TestClient(t *testing.T) {
	Expect := NewGomegaWithT(t).Expect

	expectedHost := fmt.Sprintf("https://harbor.%s.com", fake.LetterN(10))
	harborClient := NewClient(&config.HarborConfig{
		Host: expectedHost,
	})

	expectedUsername := fake.LetterN(10)
	expectedPassword := fake.LetterN(10)
	harborClientWithBasicAuth := NewClient(&config.HarborConfig{
		Host:     expectedHost,
		Username: expectedUsername,
		Password: expectedPassword,
	})

	expectedProjectName := fake.LetterN(10)
	expectedRepository := fake.LetterN(10)
	expectedTag := fake.LetterN(10)

	t.Run("insecure", func(t *testing.T) {
		harborClientInsecure := NewClient(&config.HarborConfig{
			Host:     expectedHost,
			Insecure: true,
		})

		insecureTransport := harborClientInsecure.(*client).httpClient.Transport.(*http.Transport)

		Expect(insecureTransport).ToNot(BeEquivalentTo(http.DefaultTransport))
	})

	t.Run("GetArtifacts", func(t *testing.T) {
		expectedArtifacts := randomArtifacts()
		expectedArtifactsResponseBytes, err := json.Marshal(&expectedArtifacts)
		Expect(err).ToNot(HaveOccurred())

		expectedUrl := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts", expectedHost, expectedProjectName, expectedRepository)

		t.Run("should be successful", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, string(expectedArtifactsResponseBytes)), nil
			})

			actualArtifacts, err := harborClient.GetArtifacts(expectedProjectName, expectedRepository)
			Expect(err).ToNot(HaveOccurred())

			Expect(actualArtifacts).To(BeEquivalentTo(expectedArtifacts))
		})

		t.Run("should use basic auth if set", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			var receivedRequest *http.Request

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				receivedRequest = request

				return httpmock.NewStringResponse(http.StatusOK, string(expectedArtifactsResponseBytes)), nil
			})

			actualArtifacts, err := harborClientWithBasicAuth.GetArtifacts(expectedProjectName, expectedRepository)
			Expect(err).ToNot(HaveOccurred())

			Expect(actualArtifacts).To(BeEquivalentTo(expectedArtifacts))

			assertRequestUsesBasicAuth(t, receivedRequest, expectedUsername, expectedPassword)
		})

		t.Run("should fail if the server returns an error", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusInternalServerError, ""), errors.New("test")
			})

			actualArtifacts, err := harborClient.GetArtifacts(expectedProjectName, expectedRepository)
			Expect(err).To(HaveOccurred())

			Expect(actualArtifacts).To(BeNil())
		})

		t.Run("should fail if the server returns an unexpected response", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, "not a json response body"), nil
			})

			actualArtifacts, err := harborClient.GetArtifacts(expectedProjectName, expectedRepository)
			Expect(err).To(HaveOccurred())

			Expect(actualArtifacts).To(BeNil())
		})
	})

	t.Run("GetArtifactReport", func(t *testing.T) {
		expectedScanOverview := randomScanOverview()
		expectedScanOverviewResponseBytes, err := json.Marshal(expectedScanOverview)
		Expect(err).ToNot(HaveOccurred())

		expectedUrl := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", expectedHost, expectedProjectName, expectedRepository, expectedTag)

		t.Run("should be successful", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, string(expectedScanOverviewResponseBytes)), nil
			})

			actualReport, err := harborClient.GetArtifactReport(expectedProjectName, expectedRepository, expectedTag)
			Expect(err).ToNot(HaveOccurred())

			Expect(actualReport).To(BeEquivalentTo(expectedScanOverview.Report))
		})

		t.Run("should use basic auth if set", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			var receivedRequest *http.Request

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				receivedRequest = request

				return httpmock.NewStringResponse(http.StatusOK, string(expectedScanOverviewResponseBytes)), nil
			})

			actualReport, err := harborClientWithBasicAuth.GetArtifactReport(expectedProjectName, expectedRepository, expectedTag)
			Expect(err).ToNot(HaveOccurred())

			Expect(actualReport).To(BeEquivalentTo(expectedScanOverview.Report))

			assertRequestUsesBasicAuth(t, receivedRequest, expectedUsername, expectedPassword)
		})

		t.Run("should fail if the server returns an error", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusInternalServerError, ""), errors.New("test")
			})

			actualReport, err := harborClient.GetArtifactReport(expectedProjectName, expectedRepository, expectedTag)
			Expect(err).To(HaveOccurred())

			Expect(actualReport).To(BeNil())
		})

		t.Run("should fail if the server returns an unexpected response", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, "not a json response body"), nil
			})

			actualReport, err := harborClient.GetArtifactReport(expectedProjectName, expectedRepository, expectedTag)
			Expect(err).To(HaveOccurred())

			Expect(actualReport).To(BeNil())
		})
	})

	t.Run("GetProjectByName", func(t *testing.T) {
		expectedProject := &Project{
			Name: expectedProjectName,
			Id:   fake.Number(0, 10),
		}
		expectedProjects := append(randomProjects(), expectedProject)
		fake.ShuffleAnySlice(expectedProjects)

		expectedProjectsResponseBytes, err := json.Marshal(&expectedProjects)
		Expect(err).ToNot(HaveOccurred())

		expectedUrl := fmt.Sprintf("%s/api/v2.0/projects?name=%s", expectedHost, expectedProjectName)

		t.Run("should be successful", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, string(expectedProjectsResponseBytes)), nil
			})

			actualProject, err := harborClient.GetProjectByName(expectedProjectName)
			Expect(err).ToNot(HaveOccurred())

			Expect(actualProject).To(BeEquivalentTo(expectedProject))
		})

		t.Run("should use basic auth if set", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			var receivedRequest *http.Request

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				receivedRequest = request

				return httpmock.NewStringResponse(http.StatusOK, string(expectedProjectsResponseBytes)), nil
			})

			actualProject, err := harborClientWithBasicAuth.GetProjectByName(expectedProjectName)
			Expect(err).ToNot(HaveOccurred())

			Expect(actualProject).To(BeEquivalentTo(expectedProject))

			assertRequestUsesBasicAuth(t, receivedRequest, expectedUsername, expectedPassword)
		})

		t.Run("should fail if the server returns an error", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusInternalServerError, ""), errors.New("test")
			})

			actualProject, err := harborClient.GetProjectByName(expectedProjectName)
			Expect(err).To(HaveOccurred())

			Expect(actualProject).To(BeNil())
		})

		t.Run("should fail if the server returns an unexpected response", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, "not a json response body"), nil
			})

			actualProject, err := harborClient.GetProjectByName(expectedProjectName)
			Expect(err).To(HaveOccurred())

			Expect(actualProject).To(BeNil())
		})
	})

	t.Run("GetArtifactUrl", func(t *testing.T) {
		expectedArtifactRef := fake.LetterN(10)
		expectedProjectId := fake.Number(0, 10)
		expectedProject := &Project{
			Name: expectedProjectName,
			Id:   expectedProjectId,
		}
		expectedProjects := append(randomProjects(), expectedProject)
		fake.ShuffleAnySlice(expectedProjects)

		expectedProjectsResponseBytes, err := json.Marshal(&expectedProjects)
		Expect(err).ToNot(HaveOccurred())

		expectedUrl := fmt.Sprintf("%s/api/v2.0/projects?name=%s", expectedHost, expectedProjectName)
		expectedArtifactUrl := fmt.Sprintf("%s/harbor/projects/%d/repositories/%s/artifacts/%s", expectedHost, expectedProjectId, expectedRepository, expectedArtifactRef)

		t.Run("should be successful", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, string(expectedProjectsResponseBytes)), nil
			})

			actualArtifactUrl, err := harborClient.GetArtifactUrl(expectedProjectName, expectedRepository, expectedArtifactRef)
			Expect(err).ToNot(HaveOccurred())

			Expect(actualArtifactUrl).To(BeEquivalentTo(expectedArtifactUrl))
		})

		t.Run("should use basic auth if set", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			var receivedRequest *http.Request

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				receivedRequest = request

				return httpmock.NewStringResponse(http.StatusOK, string(expectedProjectsResponseBytes)), nil
			})

			actualArtifactUrl, err := harborClientWithBasicAuth.GetArtifactUrl(expectedProjectName, expectedRepository, expectedArtifactRef)
			Expect(err).ToNot(HaveOccurred())

			Expect(actualArtifactUrl).To(BeEquivalentTo(expectedArtifactUrl))

			assertRequestUsesBasicAuth(t, receivedRequest, expectedUsername, expectedPassword)
		})

		t.Run("should fail if the server returns an error", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusInternalServerError, ""), errors.New("test")
			})

			actualArtifactUrl, err := harborClient.GetArtifactUrl(expectedProjectName, expectedRepository, expectedArtifactRef)
			Expect(err).To(HaveOccurred())

			Expect(actualArtifactUrl).To(BeEmpty())
		})

		t.Run("should fail if the server returns an unexpected response", func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder(http.MethodGet, expectedUrl, func(request *http.Request) (*http.Response, error) {
				return httpmock.NewStringResponse(http.StatusOK, "not a json response body"), nil
			})

			actualArtifactUrl, err := harborClient.GetArtifactUrl(expectedProjectName, expectedRepository, expectedArtifactRef)
			Expect(err).To(HaveOccurred())

			Expect(actualArtifactUrl).To(BeEmpty())
		})
	})
}

func randomProjects() []*Project {
	var projects []*Project

	for i := 0; i < fake.Number(1, 3); i++ {
		project := &Project{
			Id:   fake.Number(20, 50),
			Name: fake.LetterN(10),
		}

		projects = append(projects, project)
	}

	return projects
}

func randomArtifacts() []*Artifact {
	var artifacts []*Artifact

	for i := 0; i < fake.Number(1, 3); i++ {
		artifact := &Artifact{
			Tags:   []*Tag{},
			Digest: fake.LetterN(10),
		}

		for j := 0; j < fake.Number(1, 3); j++ {
			artifact.Tags = append(artifact.Tags, &Tag{Name: fake.LetterN(10)})
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts
}

func randomScanOverview() *ScanOverview {
	scanOverview := &ScanOverview{
		Report: &Report{
			Scanner: &Scanner{
				Name:    fake.LetterN(10),
				Vendor:  fake.LetterN(10),
				Version: fake.LetterN(10),
			},
			Severity:        fake.LetterN(10),
			Vulnerabilities: []*Vulnerability{},
		},
	}

	for i := 0; i < fake.Number(1, 3); i++ {
		vuln := &Vulnerability{
			ID:          fmt.Sprintf("CVE-%d-%d", fake.Number(2000, 2020), fake.Number(1, 5000)),
			Package:     fake.HackerNoun(),
			Version:     fake.AppVersion(),
			Description: fake.LoremIpsumSentence(20),
			Links:       []string{},
		}

		for j := 0; j < fake.Number(1, 3); j++ {
			vuln.Links = append(vuln.Links, fake.URL())
		}

		scanOverview.Report.Vulnerabilities = append(scanOverview.Report.Vulnerabilities, vuln)
	}

	return scanOverview
}

func assertRequestUsesBasicAuth(t *testing.T, request *http.Request, username, password string) {
	Expect := NewGomegaWithT(t).Expect

	authHeader := request.Header.Get("Authorization")
	Expect(authHeader).ToNot(BeEmpty())

	parts := strings.Split(authHeader, " ")
	Expect(parts[0]).To(Equal("Basic"))

	authBytes, err := base64.StdEncoding.DecodeString(parts[1])
	Expect(err).ToNot(HaveOccurred())

	authParts := strings.Split(string(authBytes), ":")
	Expect(authParts[0]).To(Equal(username))
	Expect(authParts[1]).To(Equal(password))
}
