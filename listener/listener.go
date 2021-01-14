package listener

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
  "strings"

	"github.com/rode/collector-harbor/harbor"
	"go.uber.org/zap"

	pb "github.com/liatrio/rode-api/proto/v1alpha1"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/package_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
  "github.com/go-resty/resty/v2"
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
	//log.Info("Harbor event is here", zap.Any("event", event))

	repo := event.EventData.Repository.Name
	var occurrences []*grafeas_go_proto.Occurrence
	var scanOccurrences []*grafeas_go_proto.Occurrence
	var occurrence *grafeas_go_proto.Occurrence

	switch event.Type {
	case "PUSH_ARTIFACT":
		occurrence = createImagePushOccurrence(event.EventData, repo)
	case "SCANNING_COMPLETED":
		occurrence = createImageScanOccurrence(event.EventData, repo)
    if (event.EventData.Resources[0].ScanOverview.Report.Summary.Total > 0) {
      scanOccurrences = getImageVulnerabilities(l, event.EventData)
    }
	default:
		return
	}
	occurrences = append(occurrences, occurrence)
	occurrences = append(occurrences, scanOccurrences...)

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

	log.Debug("response payload", zap.Any("response", response))
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
          ContinuousAnalysis: 0,
				}, },
		},
	}
	return occurrence
}

func createImageScanOccurrence(eventData *harbor.EventData, repo string) *grafeas_go_proto.Occurrence {

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
          ContinuousAnalysis: 0,
				}, },
		},
	}
	return occurrence

}

func getImageVulnerabilities(l *listener, eventData *harbor.EventData) []*grafeas_go_proto.Occurrence {
	log := l.logger.Named("ProcessEvent")

	var scanOccurrences []*grafeas_go_proto.Occurrence

  client := resty.New()

	log.Info("Project is here %s", zap.Any("resp", eventData.Repository.Namespace))
	log.Info("Repository is here %s", zap.Any("resp", eventData.Repository.Name))
	log.Info("Tag is here %s", zap.Any("resp", eventData.Resources[0].Tag))
  //uri := fmt.Sprintf("http://harbor-harbor-core/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", eventData.Repository.Namespace, eventData.Repository.Name, eventData.Resources[0].Tag)
  uri := fmt.Sprintf("http://harbor-harbor-core/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", eventData.Repository.Namespace, eventData.Repository.Name, "4.6.0")

  resp, err := client.R().
      EnableTrace().
      Get(uri)
	if err != nil {
		log.Error("error reading Vulnerabilities report from Harbor", zap.NamedError("error", err))
		return scanOccurrences
	}

	log.Info("Resp is here %s", zap.Any("resp", resp.String()))
	scanOverview := &harbor.ScanOverview{}
  json.Unmarshal(resp.Body(), &scanOverview)
	//if err := json.NewDecoder(resp.RawResponse.Body).Decode(scanOverview); err != nil {
	//	log.Error("error reading Vulnerabilities report from Harbor", zap.NamedError("error", err))
	//	return scanOccurrences
	//}
	//log.Info("Scan overview is here", zap.Any("scanOverview", scanOverview))

	occurrence := &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri:  eventData.Repository.Name,
		},
		NoteName:    "projects/notes_project/notes/harbor",
		Kind:        common_go_proto.NoteKind_VULNERABILITY,
		CreateTime:  timestamppb.Now(),
		Details: &grafeas_go_proto.Occurrence_Vulnerability{
			Vulnerability: &vulnerability_go_proto.Details{
				Type:             "docker",
				Severity:         vulnerability_go_proto.Severity(vulnerability_go_proto.Severity_value[strings.ToUpper(eventData.Resources[0].ScanOverview.Report.Severity)]),
				ShortDescription: "Needs to be updated",
				RelatedUrls: []*common_go_proto.RelatedUrl{
					{
						Url: eventData.Resources[0].ResourceUrl,
					},
				},
				EffectiveSeverity: vulnerability_go_proto.Severity_CRITICAL,
				PackageIssue: []*vulnerability_go_proto.PackageIssue{
					{
						SeverityName: "test", //Needs to be updated
						AffectedLocation: &vulnerability_go_proto.VulnerabilityLocation{
							CpeUri:  eventData.Resources[0].ResourceUrl,
							Package: "test",//Needs to be updated
							Version: &package_go_proto.Version{
								Name:     eventData.Repository.Name,
								Revision: eventData.Resources[0].Digest,
								Epoch:    35,
								Kind:     package_go_proto.Version_MINIMUM,
							},
						},
					},
				},
			},
		},
	}

  scanOccurrences = append(scanOccurrences, occurrence)
	return scanOccurrences
}
