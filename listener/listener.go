package listener

import (
	"context"
	"encoding/json"
	"fmt"
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
		w.WriteHeader(http.StatusInternalServerError)
		log.Error("error reading webhook event", zap.Error(err))
		return
	}
	log = log.With(zap.Any("harbor event", event))

	var occurrences []*grafeas_go_proto.Occurrence

	if event.Type == harbor.PUSH_ARTIFACT || event.Type == harbor.SCANNING_FAILED {
		occurrences = append(occurrences, createDiscoveryOccurrence(event))
	}

	if event.Type == harbor.SCANNING_COMPLETED {
		occurrences = append(occurrences, createDiscoveryOccurrence(event))
		if event.Data.Resources[0].ScanOverview.Report.Summary.Total > 0 {
			scanOccurrences, err := l.createVulnerabilityOccurrences(event)
			if err != nil {
				log.Error("error creating occurrences for vulnerabilities", zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			occurrences = append(occurrences, scanOccurrences...)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := l.rodeClient.BatchCreateOccurrences(ctx, &pb.BatchCreateOccurrencesRequest{
		Occurrences: occurrences,
	})
	if err != nil {
		log.Error("error sending occurrences to rode", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Debug("rode response payload", zap.Any("response", response))
	w.WriteHeader(http.StatusOK)
}

func createDiscoveryOccurrence(event *harbor.Event) *grafeas_go_proto.Occurrence {
	status := discovery_go_proto.Discovered_SCANNING
	if event.Type == harbor.SCANNING_FAILED {
		status = discovery_go_proto.Discovered_FINISHED_FAILED
	} else if event.Type == harbor.SCANNING_COMPLETED {
		status = discovery_go_proto.Discovered_FINISHED_SUCCESS
	}

	return &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri: resourceUri(event),
		},
		Kind:       common_go_proto.NoteKind_DISCOVERY,
		CreateTime: eventTimestamp(event),
		Details: &grafeas_go_proto.Occurrence_Discovered{
			Discovered: &discovery_go_proto.Details{
				Discovered: &discovery_go_proto.Discovered{
					ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
					AnalysisStatus:     status,
				}},
		},
	}
}

func (l *listener) createVulnerabilityOccurrences(event *harbor.Event) ([]*grafeas_go_proto.Occurrence, error) {
	artifacts, err := l.harborClient.GetArtifacts(event.Data.Repository.Namespace, event.Data.Repository.Name)
	if err != nil {
		return nil, err
	}

	var artifactTag string
	for _, artifact := range artifacts {
		if artifact.Digest == event.Data.Resources[0].Digest {
			artifactTag = artifact.Tags[0].Name
			break
		}
	}

	if artifactTag == "" {
		return nil, fmt.Errorf("unable to find tag for artifact with uri %s", resourceUri(event))
	}

	report, err := l.harborClient.GetArtifactReport(event.Data.Repository.Namespace, event.Data.Repository.Name, artifactTag)
	if err != nil {
		return nil, err
	}

	var occurrences []*grafeas_go_proto.Occurrence
	for _, vulnerability := range report.Vulnerabilities {
		occurrence := &grafeas_go_proto.Occurrence{
			Resource: &grafeas_go_proto.Resource{
				Uri: resourceUri(event),
			},
			Kind:       common_go_proto.NoteKind_VULNERABILITY,
			CreateTime: eventTimestamp(event),
			Details: &grafeas_go_proto.Occurrence_Vulnerability{
				Vulnerability: &vulnerability_go_proto.Details{
					Type:              "docker",
					EffectiveSeverity: vulnerability_go_proto.Severity(vulnerability_go_proto.Severity_value[strings.ToUpper(vulnerability.Severity)]),
					ShortDescription:  vulnerability.Description,
					RelatedUrls:       relatedUrls(vulnerability),
					PackageIssue:      vulnPackageIssue(vulnerability),
				},
			},
		}
		occurrences = append(occurrences, occurrence)
	}

	return occurrences, nil
}

func resourceUri(event *harbor.Event) string {
	base := strings.Split(event.Data.Resources[0].ResourceUrl, ":")[0]

	return fmt.Sprintf("%s@%s", base, event.Data.Resources[0].Digest)
}

func eventTimestamp(event *harbor.Event) *timestamppb.Timestamp {
	return timestamppb.New(time.Unix(event.OccurAt, 0))
}

func relatedUrls(vuln *harbor.Vulnerability) []*common_go_proto.RelatedUrl {
	var result []*common_go_proto.RelatedUrl
	for _, link := range vuln.Links {
		result = append(result, &common_go_proto.RelatedUrl{
			Url: link,
		})
	}

	return result
}

func vulnPackageIssue(vuln *harbor.Vulnerability) []*vulnerability_go_proto.PackageIssue {
	return []*vulnerability_go_proto.PackageIssue{
		{
			AffectedLocation: &vulnerability_go_proto.VulnerabilityLocation{
				CpeUri:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.ID),
				Package: vuln.Package,
				Version: &package_go_proto.Version{
					Name: vuln.Package,
					Kind: package_go_proto.Version_NORMAL,
				},
			},
		},
	}
}
