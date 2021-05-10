package listener

import (
	. "github.com/onsi/ginkgo"
	"github.com/rode/collector-harbor/harbor"
	"github.com/rode/collector-harbor/mocks"
	"net/http/httptest"
)

var _ = Describe("listener", func() {
	var (
		recorder     *httptest.ResponseRecorder
		harborClient harbor.Client
	)

	BeforeEach(func() {
		recorder = httptest.NewRecorder()
		harborClient = &mocks.FakeClient{}
	})
})
