package listener

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/rode/collector-harbor/config"
	"github.com/rode/collector-harbor/harbor"
	"go.uber.org/zap"

	pb "github.com/liatrio/rode-api/proto/v1alpha1"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/package_go_proto"
	"github.com/liatrio/rode-api/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type listener struct {
	rodeClient   pb.RodeClient
	logger       *zap.Logger
	config       *config.Config
	harborClient harbor.Client
}

type Listener interface {
	ProcessEvent(http.ResponseWriter, *http.Request)
}

// NewListener instantiates a listener including a zap logger and the rodeclient connection
func NewListener(logger *zap.Logger, rodeClient pb.RodeClient, config *config.Config, harborClient harbor.Client) Listener {
	return &listener{
		rodeClient:   rodeClient,
		logger:       logger,
		config:       config,
		harborClient: harborClient,
	}
}

// ProcessEvent handles incoming webhook events
func (l *listener) ProcessEvent(w http.ResponseWriter, request *http.Request) {

	log := l.logger.Named("ProcessEvent")

	event := &harbor.Event{}
	if err := json.NewDecoder(request.Body).Decode(event); err != nil {
		w.WriteHeader(http.StatusInternalServerError) // use enum instead of literal
		fmt.Fprintf(w, "error reading webhook event")
		log.Error("error reading webhook event", zap.NamedError("error", err))
		return
	}
	log.Info("Harbor event is here", zap.Any("event", event))

	repo := event.EventData.Repository.Name
	var occurrences []*grafeas_go_proto.Occurrence
	var occurrence *grafeas_go_proto.Occurrence

	switch event.Type {
	case "PUSH_ARTIFACT": // use an enum here
		occurrence = createImagePushOccurrence(event.EventData, repo)
	case "SCANNING_FAILED": // come back to this..
		occurrence = createImagePushOccurrence(event.EventData, repo)
	case "SCANNING_COMPLETED":
		occurrence = createImageScanOccurrence(event.EventData, repo)
		if event.EventData.Resources[0].ScanOverview.Report.Summary.Total > 0 {
			scanOccurrences, err := l.getImageVulnerabilities(event.EventData)
			if err != nil {
				log.Error("Error creating occurrences for vulnerabilities", zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			occurrences = append(occurrences, scanOccurrences...)
		}
	default:
		return
	}
	occurrences = append(occurrences, occurrence)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	response, err := l.rodeClient.BatchCreateOccurrences(ctx, &pb.BatchCreateOccurrencesRequest{
		Occurrences: occurrences,
	})
	if err != nil {
		log.Error("error sending occurrences to rode", zap.NamedError("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Debug("response payload", zap.Any("response", response))
	w.WriteHeader(http.StatusOK)
}

func createImagePushOccurrence(eventData *harbor.EventData, repo string) *grafeas_go_proto.Occurrence {
	occurrence := &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri: repo,
		},
		NoteName:   "projects/notes_project/notes/harbor",
		Kind:       common_go_proto.NoteKind_DISCOVERY,
		CreateTime: timestamppb.Now(),
		Details: &grafeas_go_proto.Occurrence_Discovered{
			Discovered: &discovery_go_proto.Details{
				Discovered: &discovery_go_proto.Discovered{
					ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
					AnalysisStatus:     discovery_go_proto.Discovered_SCANNING,
				}},
		},
	}
	return occurrence
}

func createImageScanOccurrence(eventData *harbor.EventData, repo string) *grafeas_go_proto.Occurrence {

	occurrence := &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri: repo,
		},
		NoteName:   "projects/notes_project/notes/harbor",
		Kind:       common_go_proto.NoteKind_DISCOVERY,
		CreateTime: timestamppb.Now(),
		Details: &grafeas_go_proto.Occurrence_Discovered{
			Discovered: &discovery_go_proto.Details{
				Discovered: &discovery_go_proto.Discovered{
					ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
					AnalysisStatus:     discovery_go_proto.Discovered_FINISHED_SUCCESS,
				}},
		},
	}
	return occurrence

}

func (l *listener) getImageVulnerabilities(eventData *harbor.EventData) ([]*grafeas_go_proto.Occurrence, error) {
	log := l.logger.Named("ProcessEvent")

	var scanOccurrences []*grafeas_go_proto.Occurrence

	uri := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts", l.config.HarborHost, eventData.Repository.Namespace, eventData.Repository.Name)
	resp, err := http.Get(uri)
	if err != nil {
		log.Error("Error finding Tag for image", zap.String("image", eventData.Repository.RepoFullName), zap.Error(err))
		return nil, err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	artifacts := []*harbor.Artifact{}
	json.Unmarshal(body, &artifacts)

	uri = fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", l.config.HarborHost, eventData.Repository.Namespace, eventData.Repository.Name, artifacts[0].Tags[0].Name)
	resp, err = http.Get(uri)
	if err != nil {
		log.Error("error reading Vulnerabilities report from Harbor", zap.Error(err))
		return nil, err
	}

	body, _ = ioutil.ReadAll(resp.Body)
	scanOverview := &harbor.ScanOverview{}
	json.Unmarshal(body, scanOverview)

	for _, vulnerability := range scanOverview.Report.Vulnerabilities {
		occurrence := &grafeas_go_proto.Occurrence{
			Resource: &grafeas_go_proto.Resource{
				Uri: eventData.Repository.RepoFullName,
			},
			NoteName:   "projects/notes_project/notes/harbor",
			Kind:       common_go_proto.NoteKind_VULNERABILITY,
			CreateTime: timestamppb.Now(),
			Details: &grafeas_go_proto.Occurrence_Vulnerability{
				Vulnerability: &vulnerability_go_proto.Details{
					Type:             "docker",
					Severity:         vulnerability_go_proto.Severity(vulnerability_go_proto.Severity_value[strings.ToUpper(vulnerability.Severity)]),
					ShortDescription: vulnerability.Description,
					RelatedUrls: []*common_go_proto.RelatedUrl{
						{
							Url: eventData.Resources[0].ResourceUrl,
						},
					},
					EffectiveSeverity: vulnerability_go_proto.Severity_CRITICAL,
					PackageIssue: []*vulnerability_go_proto.PackageIssue{
						{
							SeverityName: vulnerability.Severity,
							AffectedLocation: &vulnerability_go_proto.VulnerabilityLocation{
								CpeUri:  eventData.Resources[0].ResourceUrl,
								Package: vulnerability.Package,
								Version: &package_go_proto.Version{
									Name:     vulnerability.Package,
									Revision: vulnerability.Version,
									Kind:     package_go_proto.Version_MINIMUM,
								},
							},
						},
					},
				},
			},
		}
		scanOccurrences = append(scanOccurrences, occurrence)
	}

	return scanOccurrences, nil
}
