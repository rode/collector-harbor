package listener

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rode/collector-harbor/harbor"
)

var _ = Describe("listener", func() {

	var (
		listener        Listener
		rodeClient      *mockRodeClient
		imagePushEvent  *harbor.Event
    /* TODO: Uncomment after properly processing events */
		//imageScanEvent  *harbor.Event
		basicResource   *harbor.Resource
		basicRepository *harbor.Repository
		basicResources  []*harbor.Resource
	)

	BeforeEach(func() {

		basicRepository = &harbor.Repository{
			DateCreated:  1610046898,
			Name:         "traefik",
			Namespace:    "library",
			RepoFullName: "library/traefik",
			RepoType:     "public",
		}

		basicResource = &harbor.Resource{
			Digest:      "sha256:03e2149c3a844ca9543edd2a7a8cd0e4a1a9afb543486ad99e737323eb5c25f2",
			Tag:         "v2.3",
			ResourceUrl: "core.harbor.domain/library/traefik:v2.3",
		}

		basicResources = append(basicResources, basicResource)

		imagePushEvent = &harbor.Event{
			Type:     "PUSH_ARTIFACT",
			OccurAt:  1610046898,
			Operator: "admin",
			EventData: &harbor.EventData{
				Resources:  basicResources,
				Repository: basicRepository,
			}}

    /* TODO: Uncomment after properly processing events */
		//imageScanEvent = &harbor.Event{
		//	Type:     "SCANNING_COMPLETED",
		//	OccurAt:  1610046898,
		//	Operator: "admin",
		//	EventData: &harbor.EventData{
		//		Resources:  basicResources,
		//		Repository: basicRepository,
		//	}}

		rodeClient = &mockRodeClient{}
		listener = NewListener(logger, rodeClient)
		rodeClient.expectedError = nil
	})

	Context("determining Resource URI", func() {
		When("using Sonarqube Community Edition", func() {
			It("should be based on a passed in resource uri prefix", func() {
				Expect(imagePushEvent.EventData.Repository.Name).To(Equal("traefik"))
			})
		})

	})
	Context("processing incoming event", func() {
		var (
			body []byte
			rr   *httptest.ResponseRecorder
		)

		JustBeforeEach(func() {
			req, _ := http.NewRequest("POST", "/webhook/event", bytes.NewBuffer(body))
			rr = httptest.NewRecorder()
			handler := http.HandlerFunc(listener.ProcessEvent)
			handler.ServeHTTP(rr, req)
		})

		When("using a valid image push event", func() {
			BeforeEach(func() {
				body, _ = json.Marshal(imagePushEvent)
			})

			It("should not error out", func() {
				Expect(rr.Result().StatusCode).To(Equal(200))
			})
		})

    /* TODO: Uncomment after properly processing events */
		//When("using a valid image scan event", func() {
		//	BeforeEach(func() {
		//		body, _ = json.Marshal(imageScanEvent)
		//	})

		//	It("should not error out", func() {
		//		Expect(rr.Result().StatusCode).To(Equal(200))
		//	})
		//})

		When("using an invalid event", func() {
			BeforeEach(func() {
				body = []byte("Bad object")
			})

			It("should return a bad response", func() {
				Expect(rr.Code).To(Equal(500))
				Expect(rr.Body.String()).To(ContainSubstring("error reading webhook event"))
			})
		})

		When("failing to create occurrences", func() {
			BeforeEach(func() {
				rodeClient.expectedError = errors.New("FAILED")
				body, _ = json.Marshal(imagePushEvent)
			})

			It("should return a bad response", func() {
				Expect(rr.Code).To(Equal(500))
			})
		})
	})
})
