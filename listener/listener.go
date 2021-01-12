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
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/package_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	log.Info("Harbor event is here", zap.Any("event", event))

	repo := event.EventData.Repository.Name
	var occurrences []*grafeas_go_proto.Occurrence
	var occurrence *grafeas_go_proto.Occurrence

	switch event.Type {
	case "PUSH_ARTIFACT":
		occurrence = createImagePushOccurrence(event.EventData, repo)
	case "SCANNING_COMPLETED":
		occurrence = createImageScanVulnerabilityOccurrence(event.EventData, repo)
	default:
		return
	}
	occurrences = append(occurrences, occurrence)

	log.Info("Occurrence is here", zap.Any("occurrence", occurrence))

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

	//log.Info("response payload", zap.Any("response", response.GetOccurrences()))
	w.WriteHeader(200)
}

func createImagePushOccurrence(eventData *harbor.EventData, repo string) *grafeas_go_proto.Occurrence {
	occurrence := &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri:  repo,
		},
		NoteName:    "projects/notes_project/notes/harbor",
		Kind:        common_go_proto.NoteKind_DISCOVERY,
		CreateTime:  timestamppb.Now(),
		Details: &grafeas_go_proto.Occurrence_Discovered{
			Discovered: &discovery_go_proto.Details{
				Discovered : &discovery_go_proto.Discovered {
          ContinuousAnalysis:    0,
				},
			},
		},
	}
	return occurrence
}

func createImageScanVulnerabilityOccurrence(eventData *harbor.EventData, repo string) *grafeas_go_proto.Occurrence {
	occurrence := &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri:  repo,
		},
		NoteName:    "projects/notes_project/notes/harbor",
		Kind:        common_go_proto.NoteKind_VULNERABILITY,
		CreateTime:  timestamppb.Now(),
		Details: &grafeas_go_proto.Occurrence_Vulnerability{
			Vulnerability: &vulnerability_go_proto.Details{
				Type:             "docker",
				Severity:         vulnerability_go_proto.Severity_CRITICAL,
				ShortDescription: fmt.Sprintf("Image %s scanned", repo),
				RelatedUrls: []*common_go_proto.RelatedUrl{
					{
						Url: eventData.Resources[0].ResourceUrl,
					},
				},
				EffectiveSeverity: vulnerability_go_proto.Severity_CRITICAL,
				PackageIssue: []*vulnerability_go_proto.PackageIssue{
					{
						SeverityName: "test",
						AffectedLocation: &vulnerability_go_proto.VulnerabilityLocation{
							CpeUri:  eventData.Resources[0].ResourceUrl,
							Package: "test",
							Version: &package_go_proto.Version{
								Name:     "test",
								Revision: "test",
								Epoch:    35,
								Kind:     package_go_proto.Version_MINIMUM,
							},
						},
					},
				},
			},
		},
	}
	return occurrence
}
