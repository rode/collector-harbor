package listener

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rode/collector-harbor/harbor"
	"go.uber.org/zap"

	pb "github.com/liatrio/rode-api/proto/v1alpha1"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
)

type listener struct {
	rodeClient pb.RodeClient
	logger     *zap.Logger
}

type Listener interface {
	ProcessEvent(http.ResponseWriter, *http.Request)
}

// NewListener instantiates a listener including a zap logger and the rodeclient connection
func NewListener(logger *zap.Logger, client pb.RodeClient) Listener {
	return &listener{
		rodeClient: client,
		logger:     logger,
	}
}

// ProcessEvent handles incoming webhook events
func (l *listener) ProcessEvent(w http.ResponseWriter, request *http.Request) {
	log := l.logger.Named("ProcessEvent")

	event := &harbor.Event{}
	if err := json.NewDecoder(request.Body).Decode(event); err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "error reading webhook event")
		log.Error("error reading webhook event", zap.NamedError("error", err))
		return
	}

	log.Debug("received harbor event", zap.Any("event", event), zap.Any("project", event.ID), zap.Any("ID", event.ID))

	var occurrences []*grafeas_go_proto.Occurrence
	// for _, condition := range event.QualityGate.Conditions {
	// 	log.Debug("harbor event quality gate condition", zap.Any("condition", condition))
	// 	occurrence := createQualityGateOccurrence(condition, repo)
	// 	occurrences = append(occurrences, occurrence)
	// }

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := l.rodeClient.BatchCreateOccurrences(ctx, &pb.BatchCreateOccurrencesRequest{
		Occurrences: occurrences,
	})
	if err != nil {
		log.Error("error sending occurrences to rode", zap.NamedError("error", err))
		w.WriteHeader(500)
		return
	}

	log.Debug("response payload", zap.Any("response", response.GetOccurrences()))
	w.WriteHeader(200)
}
