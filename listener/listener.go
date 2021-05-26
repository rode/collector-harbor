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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rode/collector-harbor/harbor"
	"go.uber.org/zap"

	pb "github.com/rode/rode/proto/v1alpha1"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/package_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type listener struct {
	rodeClient   pb.RodeClient
	logger       *zap.Logger
	harborClient harbor.Client
}

type Listener interface {
	ProcessEvent(http.ResponseWriter, *http.Request)
}

// NewListener instantiates a listener including a zap logger and the rodeclient connection
func NewListener(logger *zap.Logger, rodeClient pb.RodeClient, harborClient harbor.Client) Listener {
	return &listener{
		rodeClient:   rodeClient,
		logger:       logger,
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

	// only process events that occur when scanning is finished
	if event.Type != harbor.SCANNING_FAILED && event.Type != harbor.SCANNING_COMPLETED {
		w.WriteHeader(http.StatusOK)
		log.Debug(fmt.Sprintf("not processing event with type %s", event.Type))
		return
	}

	log = log.With(zap.Any("harbor event", event))
	log.Debug("received event from harbor")

	for _, resource := range event.Data.Resources {
		if resource.ScanOverview.Report == nil {
			log.Error("expected event resource to contain a report")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err := l.processEventResource(event, resource)
		if err != nil {
			log.Error("error processing event resource", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (l *listener) processEventResource(event *harbor.Event, resource *harbor.Resource) error {
	log := l.logger.Named("processEventResource").With(zap.Any("resource", resource))
	log.Debug("processing event resource")

	report := resource.ScanOverview.Report

	// allow for one minute to process this event resource
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	log.Debug("creating note")
	noteName, err := l.createNoteForReport(ctx, event, resource, report)
	if err != nil {
		return fmt.Errorf("error creating note for scan: %v", err)
	}

	var occurrences []*grafeas_go_proto.Occurrence

	log.Debug("creating discovery occurrences")
	discoveryOccurrences, err := createDiscoveryOccurrences(event, resource, report, noteName)
	if err != nil {
		return fmt.Errorf("error creating discovery occurrences: %v", err)
	}

	occurrences = append(occurrences, discoveryOccurrences...)

	if event.Type == harbor.SCANNING_COMPLETED && report.Summary.Total > 0 {
		log.Debug("creating vulnerability occurrences")
		scanOccurrences, err := l.createVulnerabilityOccurrences(event, resource, noteName)
		if err != nil {
			return fmt.Errorf("error creating vulnerability occurrences: %v", err)
		}

		occurrences = append(occurrences, scanOccurrences...)
	}

	log.Debug("sending occurrences to rode")
	response, err := l.rodeClient.BatchCreateOccurrences(ctx, &pb.BatchCreateOccurrencesRequest{
		Occurrences: occurrences,
	})
	if err != nil {
		return fmt.Errorf("error sending occurrences to rode: %v", err)
	}

	log.Debug("rode response payload", zap.Any("response", response))

	return nil
}

func createDiscoveryOccurrences(event *harbor.Event, resource *harbor.Resource, report *harbor.Report, noteName string) ([]*grafeas_go_proto.Occurrence, error) {
	status := discovery_go_proto.Discovered_FINISHED_SUCCESS
	if event.Type == harbor.SCANNING_FAILED {
		status = discovery_go_proto.Discovered_FINISHED_FAILED
	}

	startTime, endTime, err := reportTimestamps(report)
	if err != nil {
		return nil, err
	}

	return []*grafeas_go_proto.Occurrence{
		{
			Resource: &grafeas_go_proto.Resource{
				Uri: resourceUri(resource),
			},
			NoteName:   noteName,
			Kind:       common_go_proto.NoteKind_DISCOVERY,
			CreateTime: startTime,
			Details: &grafeas_go_proto.Occurrence_Discovered{
				Discovered: &discovery_go_proto.Details{
					Discovered: &discovery_go_proto.Discovered{
						ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
						AnalysisStatus:     discovery_go_proto.Discovered_SCANNING,
					}},
			},
		},
		{
			Resource: &grafeas_go_proto.Resource{
				Uri: resourceUri(resource),
			},
			NoteName:   noteName,
			Kind:       common_go_proto.NoteKind_DISCOVERY,
			CreateTime: endTime,
			Details: &grafeas_go_proto.Occurrence_Discovered{
				Discovered: &discovery_go_proto.Details{
					Discovered: &discovery_go_proto.Discovered{
						ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
						AnalysisStatus:     status,
					}},
			},
		},
	}, nil
}

func (l *listener) createVulnerabilityOccurrences(event *harbor.Event, resource *harbor.Resource, noteName string) ([]*grafeas_go_proto.Occurrence, error) {
	report, err := l.harborClient.GetArtifactReport(event.Data.Repository.Namespace, event.Data.Repository.Name, event.Data.Resources[0].Digest)
	if err != nil {
		return nil, err
	}

	var occurrences []*grafeas_go_proto.Occurrence
	for _, vulnerability := range report.Vulnerabilities {
		occurrence := &grafeas_go_proto.Occurrence{
			Resource: &grafeas_go_proto.Resource{
				Uri: resourceUri(resource),
			},
			NoteName:   noteName,
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

func (l *listener) createNoteForReport(ctx context.Context, event *harbor.Event, resource *harbor.Resource, report *harbor.Report) (string, error) {
	artifactUrl, err := l.harborClient.GetArtifactUrl(event.Data.Repository.Namespace, event.Data.Repository.Name, resource.Digest)
	if err != nil {
		return "", err
	}

	note, err := l.rodeClient.CreateNote(ctx, &pb.CreateNoteRequest{
		Note: &grafeas_go_proto.Note{
			ShortDescription: "Harbor Vulnerability Scan",
			LongDescription:  fmt.Sprintf("Harbor Vulnerability Scan by %s/%s (%s)", report.Scanner.Vendor, report.Scanner.Name, report.Scanner.Version),
			Kind:             common_go_proto.NoteKind_DISCOVERY,
			RelatedUrl: []*common_go_proto.RelatedUrl{
				{
					Label: "Artifact URL",
					Url:   artifactUrl,
				},
			},
			Type: &grafeas_go_proto.Note_Discovery{
				Discovery: &discovery_go_proto.Discovery{
					AnalysisKind: common_go_proto.NoteKind_VULNERABILITY,
				},
			},
		},
		NoteId: fmt.Sprintf("harbor-scan-%s", report.ReportId),
	})
	if err != nil {
		return "", err
	}

	return note.Name, nil
}

func resourceUri(resource *harbor.Resource) string {
	base := strings.Split(resource.ResourceUrl, ":")[0]

	return fmt.Sprintf("%s@%s", base, resource.Digest)
}

func eventTimestamp(event *harbor.Event) *timestamppb.Timestamp {
	return timestamppb.New(time.Unix(event.OccurAt, 0))
}

func reportTimestamps(report *harbor.Report) (*timestamppb.Timestamp, *timestamppb.Timestamp, error) {
	start, err := time.Parse(time.RFC3339Nano, report.StartTime)
	if err != nil {
		return nil, nil, err
	}

	end, err := time.Parse(time.RFC3339Nano, report.EndTime)
	if err != nil {
		return nil, nil, err
	}

	return timestamppb.New(start), timestamppb.New(end), nil
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
