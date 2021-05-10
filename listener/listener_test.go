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
			recorder                               *httptest.ResponseRecorder
			expectedPayload                        io.Reader
			expectedUrl                            string
			expectedBatchCreateOccurrencesResponse *pb.BatchCreateOccurrencesResponse
			expectedBatchCreateOccurrencesError    error
		)

		BeforeEach(func() {
			expectedUrl = fake.URL()
			recorder = httptest.NewRecorder()

			expectedBatchCreateOccurrencesResponse = &pb.BatchCreateOccurrencesResponse{}
			expectedBatchCreateOccurrencesError = nil
		})

		JustBeforeEach(func() {
			rodeClient.BatchCreateOccurrencesReturns(expectedBatchCreateOccurrencesResponse, expectedBatchCreateOccurrencesError)

			listener.ProcessEvent(recorder, httptest.NewRequest("POST", "/webhook/event", expectedPayload))
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

		When("a push event is received", func() {
			BeforeEach(func() {
				expectedPayload = structToJsonBody(&harbor.Event{
					Type:    harbor.PUSH_ARTIFACT,
					OccurAt: generateRandomTime(),
					Data: &harbor.EventData{
						Resources: []*harbor.Resource{
							generateRandomResource(expectedUrl),
						},
					},
				})
			})

			It("should create a single scanning discovery occurrence", func() {
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

				_, batchCreateOccurrencesRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(batchCreateOccurrencesRequest.Occurrences).To(HaveLen(1))

				discoveryOccurrence := batchCreateOccurrencesRequest.Occurrences[0]
				Expect(discoveryOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(discoveryOccurrence.NoteName).To(Equal("projects/rode/notes/harbor"))
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

		When("a scanning failed event is received", func() {
			BeforeEach(func() {
				expectedPayload = structToJsonBody(&harbor.Event{
					Type:    harbor.SCANNING_FAILED,
					OccurAt: generateRandomTime(),
					Data: &harbor.EventData{
						Resources: []*harbor.Resource{
							generateRandomResource(expectedUrl),
						},
					},
				})
			})

			It("should create a single scanning failed discovery occurrence", func() {
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

				_, batchCreateOccurrencesRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(batchCreateOccurrencesRequest.Occurrences).To(HaveLen(1))

				discoveryOccurrence := batchCreateOccurrencesRequest.Occurrences[0]
				Expect(discoveryOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(discoveryOccurrence.NoteName).To(Equal("projects/rode/notes/harbor"))
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
