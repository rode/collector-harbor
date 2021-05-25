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
		listener     Listener
	)

	BeforeEach(func() {
		harborClient = &mocks.FakeClient{}
		rodeClient = &mocks.FakeRodeClient{}
	})

	JustBeforeEach(func() {
		listener = NewListener(logger, rodeClient, harborClient)
	})

	Context("ProcessEvent", func() {
		var (
			recorder            *httptest.ResponseRecorder
			expectedHarborEvent *harbor.Event
			expectedPayload     io.Reader
			expectedUrl         string

			expectedBatchCreateOccurrencesResponse *pb.BatchCreateOccurrencesResponse
			expectedBatchCreateOccurrencesError    error

			expectedArtifactUrl      string
			expectedArtifactUrlError error

			expectedReport                 *harbor.Report
			expectedGetArtifactReportError error

			expectedNoteName        string
			expectedNote            *grafeas_go_proto.Note
			expectedCreateNoteError error

			expectedReportId string

			expectedRepository *harbor.Repository
			expectedResource   *harbor.Resource
		)

		BeforeEach(func() {
			expectedPayload = nil
			expectedUrl = fake.URL()
			recorder = httptest.NewRecorder()

			expectedArtifactUrl = fake.URL()
			expectedArtifactUrlError = nil

			expectedReportId = fake.LetterN(10)

			expectedNoteName = fake.LetterN(10)
			expectedNote = &grafeas_go_proto.Note{
				Name: expectedNoteName,
			}
			expectedCreateNoteError = nil

			expectedBatchCreateOccurrencesResponse = &pb.BatchCreateOccurrencesResponse{}
			expectedBatchCreateOccurrencesError = nil

			expectedRepository = &harbor.Repository{
				Name:      fake.LetterN(10),
				Namespace: fake.LetterN(10),
			}
			expectedResource = generateRandomResource(expectedUrl, expectedReportId)
		})

		JustBeforeEach(func() {
			rodeClient.CreateNoteReturns(expectedNote, expectedCreateNoteError)
			rodeClient.BatchCreateOccurrencesReturns(expectedBatchCreateOccurrencesResponse, expectedBatchCreateOccurrencesError)
			harborClient.GetArtifactUrlReturns(expectedArtifactUrl, expectedArtifactUrlError)
			harborClient.GetArtifactReportReturns(expectedReport, expectedGetArtifactReportError)

			var payload io.Reader
			if expectedPayload != nil {
				payload = expectedPayload
			} else {
				payload = structToJsonBody(expectedHarborEvent)
			}

			listener.ProcessEvent(recorder, httptest.NewRequest("POST", "/webhook/event", payload))
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

			It("should not make any request to rode", func() {
				Expect(rodeClient.CreateNoteCallCount()).To(Equal(0))
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(0))
			})
		})

		When("an image is pushed", func() {
			BeforeEach(func() {
				expectedHarborEvent = &harbor.Event{
					Type:    harbor.PUSH_ARTIFACT,
					OccurAt: generateRandomTime(),
					Data: &harbor.EventData{
						Resources: []*harbor.Resource{
							expectedResource,
						},
						Repository: expectedRepository,
					},
				}
			})

			It("should respond with a 200", func() {
				Expect(recorder.Code).To(Equal(http.StatusOK))
			})

			It("should not make any request to rode", func() {
				Expect(rodeClient.CreateNoteCallCount()).To(Equal(0))
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(0))
			})

			It("should not make any requests to harbor", func() {
				Expect(harborClient.GetArtifactUrlCallCount()).To(Equal(0))
				Expect(harborClient.GetArtifactReportCallCount()).To(Equal(0))
			})
		})

		When("a scan failed", func() {
			BeforeEach(func() {
				expectedHarborEvent = &harbor.Event{
					Type:    harbor.SCANNING_FAILED,
					OccurAt: generateRandomTime(),
					Data: &harbor.EventData{
						Resources: []*harbor.Resource{
							expectedResource,
						},
						Repository: expectedRepository,
					},
				}
			})

			It("should create a note", func() {
				// artifact url should be fetched to feed the note
				Expect(harborClient.GetArtifactUrlCallCount()).To(Equal(1))
				namespace, name, digest := harborClient.GetArtifactUrlArgsForCall(0)
				Expect(namespace).To(Equal(expectedRepository.Namespace))
				Expect(name).To(Equal(expectedRepository.Name))
				Expect(digest).To(Equal(expectedResource.Digest))

				Expect(rodeClient.CreateNoteCallCount()).To(Equal(1))

				_, createNoteRequest, _ := rodeClient.CreateNoteArgsForCall(0)
				Expect(createNoteRequest.NoteId).To(Equal(fmt.Sprintf("harbor-scan-%s", expectedReportId)))

				Expect((createNoteRequest.Note.Type).(*grafeas_go_proto.Note_Discovery).Discovery.AnalysisKind).To(Equal(common_go_proto.NoteKind_VULNERABILITY))
				Expect(createNoteRequest.Note.RelatedUrl[0].Url).To(Equal(expectedArtifactUrl))
			})

			It("should create discovery occurrences for the failed scan", func() {
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

				_, batchCreateOccurrencesRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(batchCreateOccurrencesRequest.Occurrences).To(HaveLen(2))

				scanStartOccurrence := batchCreateOccurrencesRequest.Occurrences[0]
				scanEndOccurrence := batchCreateOccurrencesRequest.Occurrences[1]

				Expect(scanStartOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(scanStartOccurrence.NoteName).To(Equal(expectedNoteName))
				Expect(scanStartOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_SCANNING))

				Expect(scanEndOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(scanEndOccurrence.NoteName).To(Equal(expectedNoteName))
				Expect(scanEndOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_FINISHED_FAILED))
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
			BeforeEach(func() {
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

			It("should create a note", func() {
				// artifact url should be fetched to feed the note
				Expect(harborClient.GetArtifactUrlCallCount()).To(Equal(1))
				namespace, name, digest := harborClient.GetArtifactUrlArgsForCall(0)
				Expect(namespace).To(Equal(expectedRepository.Namespace))
				Expect(name).To(Equal(expectedRepository.Name))
				Expect(digest).To(Equal(expectedResource.Digest))

				Expect(rodeClient.CreateNoteCallCount()).To(Equal(1))

				_, createNoteRequest, _ := rodeClient.CreateNoteArgsForCall(0)
				Expect(createNoteRequest.NoteId).To(Equal(fmt.Sprintf("harbor-scan-%s", expectedReportId)))

				Expect((createNoteRequest.Note.Type).(*grafeas_go_proto.Note_Discovery).Discovery.AnalysisKind).To(Equal(common_go_proto.NoteKind_VULNERABILITY))
				Expect(createNoteRequest.Note.RelatedUrl[0].Url).To(Equal(expectedArtifactUrl))
			})

			It("should create discovery occurrences for the finished scan", func() {
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

				_, batchCreateOccurrencesRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(batchCreateOccurrencesRequest.Occurrences).To(HaveLen(2))

				scanStartOccurrence := batchCreateOccurrencesRequest.Occurrences[0]
				scanEndOccurrence := batchCreateOccurrencesRequest.Occurrences[1]

				Expect(scanStartOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(scanStartOccurrence.NoteName).To(Equal(expectedNoteName))
				Expect(scanStartOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_SCANNING))

				Expect(scanEndOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(scanEndOccurrence.NoteName).To(Equal(expectedNoteName))
				Expect(scanEndOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_FINISHED_SUCCESS))
			})

			It("should respond with a 200", func() {
				Expect(recorder.Code).To(Equal(http.StatusOK))
			})

			It("should not make any requests to harbor", func() {
				Expect(harborClient.GetArtifactsCallCount()).To(Equal(0))
				Expect(harborClient.GetArtifactReportCallCount()).To(Equal(0))
			})

			When("vulnerabilities are found", func() {
				BeforeEach(func() {
					expectedNumberOfVulns := fake.Number(2, 5)

					expectedResource.ScanOverview.Report.Summary.Total = expectedNumberOfVulns
					expectedReport = &harbor.Report{
						Summary: &harbor.Summary{
							Total: expectedNumberOfVulns,
						},
						Vulnerabilities: generateRandomVulnerabilities(expectedNumberOfVulns),
					}
				})

				It("should create two discovery occurrences, and a vulnerability occurrence for each vulnerability in the report", func() {
					Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

					_, batchCreateOccurrencesRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

					Expect(batchCreateOccurrencesRequest.Occurrences).To(HaveLen(len(expectedReport.Vulnerabilities) + 2))

					scanStartOccurrence := batchCreateOccurrencesRequest.Occurrences[0]
					scanEndOccurrence := batchCreateOccurrencesRequest.Occurrences[1]

					Expect(scanStartOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
					Expect(scanStartOccurrence.NoteName).To(Equal(expectedNoteName))
					Expect(scanStartOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_SCANNING))

					Expect(scanEndOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
					Expect(scanEndOccurrence.NoteName).To(Equal(expectedNoteName))
					Expect(scanEndOccurrence.Details.(*grafeas_go_proto.Occurrence_Discovered).Discovered.Discovered.AnalysisStatus).To(Equal(discovery_go_proto.Discovered_FINISHED_SUCCESS))

					for i := 0; i < len(expectedReport.Vulnerabilities); i++ {
						occurrence := batchCreateOccurrencesRequest.Occurrences[i+2]

						Expect(occurrence.Kind).To(Equal(common_go_proto.NoteKind_VULNERABILITY))
						Expect(occurrence.NoteName).To(Equal(expectedNoteName))
						Expect(occurrence.Details.(*grafeas_go_proto.Occurrence_Vulnerability).Vulnerability.Type).To(Equal("docker"))
					}
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

func generateRandomResource(expectedUrl, expectedReportId string) *harbor.Resource {
	randomDigest := sha256.Sum256([]byte(fake.LetterN(10)))
	randomTag := fake.LetterN(7)

	return &harbor.Resource{
		ScanOverview: &harbor.ScanOverview{
			Report: &harbor.Report{
				Summary: &harbor.Summary{
					Total: 0,
				},
				ReportId: expectedReportId,
				Scanner: &harbor.Scanner{
					Name:    fake.LetterN(10),
					Vendor:  fake.LetterN(10),
					Version: fake.LetterN(10),
				},
				StartTime: time.Now().Add(time.Duration(fake.Int64())).Format(time.RFC3339Nano),
				EndTime:   time.Now().Add(time.Duration(fake.Int64() * -1)).Format(time.RFC3339Nano),
			},
		},
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
