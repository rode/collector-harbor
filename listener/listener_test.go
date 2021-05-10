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

package listener

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rode/collector-harbor/harbor"
	"github.com/rode/collector-harbor/mocks"
	pb "github.com/rode/rode/proto/v1alpha1"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

var _ = Describe("listener", func() {
	var (
		harborClient *mocks.FakeClient
		rodeClient   *mocks.FakeRodeClient
		l            *listener

		expectedDiscoveryNoteName   string
		expectedUnspecifiedNoteName string
	)

	BeforeEach(func() {
		expectedDiscoveryNoteName = fake.LetterN(10)
		expectedUnspecifiedNoteName = fake.LetterN(10)

		harborClient = &mocks.FakeClient{}
		rodeClient = &mocks.FakeRodeClient{}
	})

	JustBeforeEach(func() {
		l = &listener{
			rodeClient:   rodeClient,
			logger:       logger,
			harborClient: harborClient,
			noteNames: map[common_go_proto.NoteKind]string{
				common_go_proto.NoteKind_DISCOVERY:             expectedDiscoveryNoteName,
				common_go_proto.NoteKind_NOTE_KIND_UNSPECIFIED: expectedUnspecifiedNoteName,
			},
		}
	})

	Context("Initialize", func() {
		var (
			actualError error

			expectedRegisterCollectorResponse *pb.RegisterCollectorResponse
			expectedRegisterCollectorError    error
		)

		BeforeEach(func() {
			expectedRegisterCollectorResponse = &pb.RegisterCollectorResponse{
				Notes: map[string]*grafeas_go_proto.Note{
					"harbor-discovery": {
						Name: expectedDiscoveryNoteName,
						Kind: common_go_proto.NoteKind_DISCOVERY,
					},
					"harbor-unspecified": {
						Name: expectedUnspecifiedNoteName,
						Kind: common_go_proto.NoteKind_NOTE_KIND_UNSPECIFIED,
					},
				},
			}
			expectedRegisterCollectorError = nil
		})

		JustBeforeEach(func() {
			rodeClient.RegisterCollectorReturns(expectedRegisterCollectorResponse, expectedRegisterCollectorError)

			actualError = NewListener(logger, rodeClient, harborClient).Initialize()
		})

		It("should register the collector and store the resulting note names", func() {
			Expect(rodeClient.RegisterCollectorCallCount()).To(Equal(1))

			Expect(l.noteNames[common_go_proto.NoteKind_DISCOVERY]).To(Equal(expectedDiscoveryNoteName))
			Expect(l.noteNames[common_go_proto.NoteKind_NOTE_KIND_UNSPECIFIED]).To(Equal(expectedUnspecifiedNoteName))
		})

		It("should not return an error", func() {
			Expect(actualError).ToNot(HaveOccurred())
		})

		When("registering the collector results in an error", func() {
			BeforeEach(func() {
				expectedRegisterCollectorError = errors.New("error registering collector")
			})

			It("should return an error", func() {
				Expect(actualError).To(HaveOccurred())
			})
		})
	})

	Context("ProcessEvent", func() {
		var (
			recorder            *httptest.ResponseRecorder
			expectedHarborEvent *harbor.Event
			expectedPayload     io.Reader
			expectedUrl         string

			expectedBatchCreateOccurrencesResponse *pb.BatchCreateOccurrencesResponse
			expectedBatchCreateOccurrencesError    error

			expectedArtifact          *harbor.Artifact
			expectedGetArtifactsError error

			expectedReport                 *harbor.Report
			expectedGetArtifactReportError error
		)

		BeforeEach(func() {
			expectedPayload = nil
			expectedUrl = fake.URL()
			recorder = httptest.NewRecorder()

			expectedBatchCreateOccurrencesResponse = &pb.BatchCreateOccurrencesResponse{}
			expectedBatchCreateOccurrencesError = nil
		})

		JustBeforeEach(func() {
			rodeClient.BatchCreateOccurrencesReturns(expectedBatchCreateOccurrencesResponse, expectedBatchCreateOccurrencesError)
			harborClient.GetArtifactsReturns([]*harbor.Artifact{expectedArtifact}, expectedGetArtifactsError)
			harborClient.GetArtifactReportReturns(expectedReport, expectedGetArtifactReportError)

			var payload io.Reader
			if expectedPayload != nil {
				payload = expectedPayload
			} else {
				payload = structToJsonBody(expectedHarborEvent)
			}

			l.ProcessEvent(recorder, httptest.NewRequest("POST", "/webhook/event", payload))
		})

		When("an invalid event is sent", func() {
			BeforeEach(func() {
				expectedPayload = strings.NewReader("invalid json")
			})

			It("should respond with an error", func() {
				Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
			})

			It("should not create any occurrences", func() {
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(0))
			})

			It("should not make any requests to harbor", func() {
				Expect(harborClient.GetArtifactsCallCount()).To(Equal(0))
				Expect(harborClient.GetArtifactReportCallCount()).To(Equal(0))
			})
		})

		When("an image is pushed", func() {
			BeforeEach(func() {
				expectedHarborEvent = &harbor.Event{
					Type:    harbor.PUSH_ARTIFACT,
					OccurAt: generateRandomTime(),
					Data: &harbor.EventData{
						Resources: []*harbor.Resource{
							generateRandomResource(expectedUrl),
						},
					},
				}
			})

			It("should create a single scanning discovery occurrence", func() {
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

				_, batchCreateOccurrencesRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(batchCreateOccurrencesRequest.Occurrences).To(HaveLen(1))

				discoveryOccurrence := batchCreateOccurrencesRequest.Occurrences[0]
				Expect(discoveryOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(discoveryOccurrence.NoteName).To(Equal(expectedDiscoveryNoteName))
				Expect(discoveryOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_SCANNING))
			})

			It("should respond with a 200", func() {
				Expect(recorder.Code).To(Equal(http.StatusOK))
			})

			It("should not make any requests to harbor", func() {
				Expect(harborClient.GetArtifactsCallCount()).To(Equal(0))
				Expect(harborClient.GetArtifactReportCallCount()).To(Equal(0))
			})

			When("creating the occurrence fails", func() {
				BeforeEach(func() {
					expectedBatchCreateOccurrencesError = errors.New("failed creating occurrence")
				})

				It("should respond with an error", func() {
					Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
				})
			})
		})

		When("a scan failed", func() {
			BeforeEach(func() {
				expectedHarborEvent = &harbor.Event{
					Type:    harbor.SCANNING_FAILED,
					OccurAt: generateRandomTime(),
					Data: &harbor.EventData{
						Resources: []*harbor.Resource{
							generateRandomResource(expectedUrl),
						},
					},
				}
			})

			It("should create a single scanning failed discovery occurrence", func() {
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

				_, batchCreateOccurrencesRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(batchCreateOccurrencesRequest.Occurrences).To(HaveLen(1))

				discoveryOccurrence := batchCreateOccurrencesRequest.Occurrences[0]
				Expect(discoveryOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(discoveryOccurrence.NoteName).To(Equal(expectedDiscoveryNoteName))
				Expect(discoveryOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_FINISHED_FAILED))
			})

			It("should respond with a 200", func() {
				Expect(recorder.Code).To(Equal(http.StatusOK))
			})

			It("should not make any requests to harbor", func() {
				Expect(harborClient.GetArtifactsCallCount()).To(Equal(0))
				Expect(harborClient.GetArtifactReportCallCount()).To(Equal(0))
			})
		})

		When("a scan is completed", func() {
			var (
				expectedResource   *harbor.Resource
				expectedRepository *harbor.Repository
			)

			BeforeEach(func() {
				expectedResource = generateRandomResource(expectedUrl)

				// happy path: no vulns found
				expectedResource.ScanOverview = &harbor.ScanOverview{
					Report: &harbor.Report{
						Summary: &harbor.Summary{
							Total: 0,
						},
					},
				}
				expectedRepository = &harbor.Repository{
					Name:      fake.LetterN(10),
					Namespace: fake.LetterN(10),
				}

				expectedHarborEvent = &harbor.Event{
					Type:    harbor.SCANNING_COMPLETED,
					OccurAt: generateRandomTime(),
					Data: &harbor.EventData{
						Resources: []*harbor.Resource{
							expectedResource,
						},
						Repository: expectedRepository,
					},
				}
			})

			It("should create a single scanning success discovery occurrence", func() {
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

				_, batchCreateOccurrencesRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(batchCreateOccurrencesRequest.Occurrences).To(HaveLen(1))

				discoveryOccurrence := batchCreateOccurrencesRequest.Occurrences[0]
				Expect(discoveryOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(discoveryOccurrence.NoteName).To(Equal(expectedDiscoveryNoteName))
				Expect(discoveryOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_FINISHED_SUCCESS))
			})

			It("should respond with a 200", func() {
				Expect(recorder.Code).To(Equal(http.StatusOK))
			})

			It("should not make any requests to harbor", func() {
				Expect(harborClient.GetArtifactsCallCount()).To(Equal(0))
				Expect(harborClient.GetArtifactReportCallCount()).To(Equal(0))
			})

			When("vulnerabilities are found", func() {
				var (
					expectedArtifactTag string
				)

				BeforeEach(func() {
					expectedArtifactTag = fake.LetterN(10)
					expectedArtifact = &harbor.Artifact{
						Tags: []*harbor.Tag{
							{
								Name: expectedArtifactTag,
							},
						},
						Digest: expectedResource.Digest,
					}
					expectedGetArtifactsError = nil

					expectedNumberOfVulns := fake.Number(2, 5)
					expectedResource.ScanOverview.Report.Summary.Total = expectedNumberOfVulns

					expectedReport = &harbor.Report{
						Vulnerabilities: generateRandomVulnerabilities(expectedNumberOfVulns),
					}
				})

				It("should fetch the artifacts from the event", func() {
					Expect(harborClient.GetArtifactsCallCount()).To(Equal(1))

					namespace, name := harborClient.GetArtifactsArgsForCall(0)

					Expect(namespace).To(Equal(expectedRepository.Namespace))
					Expect(name).To(Equal(expectedRepository.Name))
				})

				It("should create a discovery occurrence and a vulnerability occurrence for each vulnerability in the report", func() {
					Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

					_, batchCreateOccurrencesRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

					Expect(batchCreateOccurrencesRequest.Occurrences).To(HaveLen(len(expectedReport.Vulnerabilities) + 1))

					discoveryOccurrence := batchCreateOccurrencesRequest.Occurrences[0]
					Expect(discoveryOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
					Expect(discoveryOccurrence.NoteName).To(Equal(expectedDiscoveryNoteName))
					Expect(discoveryOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_FINISHED_SUCCESS))

					for i := 0; i < len(expectedReport.Vulnerabilities); i++ {
						occurrence := batchCreateOccurrencesRequest.Occurrences[i+1]

						Expect(occurrence.Kind).To(Equal(common_go_proto.NoteKind_VULNERABILITY))
						Expect(occurrence.NoteName).To(Equal(expectedUnspecifiedNoteName))
						Expect(occurrence.Details.(*grafeas_go_proto.Occurrence_Vulnerability).Vulnerability.Type).To(Equal("docker"))
					}
				})

				It("should respond with a 200", func() {
					Expect(recorder.Code).To(Equal(http.StatusOK))
				})

				When("getting artifacts fails", func() {
					BeforeEach(func() {
						expectedGetArtifactsError = errors.New("failed getting artifacts")
					})

					It("should respond with an error", func() {
						Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
					})

					It("should not attempt to fetch a report", func() {
						Expect(harborClient.GetArtifactReportCallCount()).To(Equal(0))
					})

					It("should not create any occurrences", func() {
						Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(0))
					})
				})

				When("the artifact tag can't be found", func() {
					BeforeEach(func() {
						expectedArtifact.Digest = fake.LetterN(10)
					})

					It("should respond with an error", func() {
						Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
					})

					It("should not attempt to fetch a report", func() {
						Expect(harborClient.GetArtifactReportCallCount()).To(Equal(0))
					})

					It("should not create any occurrences", func() {
						Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(0))
					})
				})

				When("getting the artifact report fails", func() {
					BeforeEach(func() {
						expectedGetArtifactReportError = errors.New("failed getting artifact report")
					})

					It("should respond with an error", func() {
						Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
					})

					It("should not create any occurrences", func() {
						Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(0))
					})
				})
			})
		})
	})
})

func structToJsonBody(i interface{}) io.ReadCloser {
	b, err := json.Marshal(i)
	Expect(err).ToNot(HaveOccurred())

	return ioutil.NopCloser(strings.NewReader(string(b)))
}

func generateRandomTime() int64 {
	return time.Now().Unix() + int64(fake.Number(-1000, 1000))
}

func generateRandomResource(expectedUrl string) *harbor.Resource {
	randomDigest := sha256.Sum256([]byte(fake.LetterN(10)))
	randomTag := fake.LetterN(7)

	return &harbor.Resource{
		Digest:      fmt.Sprintf("sha256:%x", randomDigest),
		Tag:         randomTag,
		ResourceUrl: fmt.Sprintf("%s:%s", expectedUrl, randomTag),
	}
}

func generateRandomVulnerabilities(num int) []*harbor.Vulnerability {
	var severities []string
	for k := range vulnerability_go_proto.Severity_value {
		severities = append(severities, k)
	}

	var vulns []*harbor.Vulnerability
	for i := 0; i < num; i++ {
		vulns = append(vulns, &harbor.Vulnerability{
			ID:          fmt.Sprintf("CVE-%d", fake.Number(100, 999)),
			Description: fake.Sentence(10),
			Links:       strings.Split(fake.Sentence(10), " "),
			Package:     fake.LetterN(20),
			Severity:    fake.RandomString(severities),
		})
	}

	return vulns
}
