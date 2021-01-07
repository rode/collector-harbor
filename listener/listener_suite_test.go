package listener

import (
	"context"
	"io/ioutil"
	"log"
	"testing"

	pb "github.com/liatrio/rode-api/proto/v1alpha1"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var logger *zap.Logger

func TestListener(t *testing.T) {
	RegisterFailHandler(Fail)
	log.SetOutput(ioutil.Discard)
	RunSpecs(t, "Listener Suite")
}

var _ = BeforeSuite(func() {
	logger, _ = zap.NewDevelopment()
})

type mockRodeClient struct {
	receivedBatchCreateOccurrenceRequest  *pb.BatchCreateOccurrencesRequest
	preparedBatchCreateOccurrenceResponse *pb.BatchCreateOccurrencesResponse
	expectedError                         error
}

func (m *mockRodeClient) BatchCreateOccurrences(ctx context.Context, in *pb.BatchCreateOccurrencesRequest, opts ...grpc.CallOption) (*pb.BatchCreateOccurrencesResponse, error) {
	m.receivedBatchCreateOccurrenceRequest = in

	// if we have a prepared response, send it. otherwise, return nil
	if m.preparedBatchCreateOccurrenceResponse != nil {
		return m.preparedBatchCreateOccurrenceResponse, m.expectedError
	}

	return nil, m.expectedError
}
