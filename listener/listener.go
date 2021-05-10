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
	noteNames    map[common_go_proto.NoteKind]string
}

type Listener interface {
	ProcessEvent(http.ResponseWriter, *http.Request)
	Initialize() error
}

// NewListener instantiates a listener including a zap logger and the rodeclient connection
func NewListener(logger *zap.Logger, rodeClient pb.RodeClient, harborClient harbor.Client) Listener {
	return &listener{
		rodeClient:   rodeClient,
		logger:       logger,
		harborClient: harborClient,
	}
}

// Initialize registers the collector with Rode
func (l *listener) Initialize() error {
	log := l.logger.Named("Initialize")

	registerCollectorRequest := &pb.RegisterCollectorRequest{
		Id: "harbor",
		Notes: []*grafeas_go_proto.Note{
			// discovery note will be used to identify the type of scan
			{
				ShortDescription: "Harbor Vulnerability Scan",
				LongDescription:  "Harbor Vulnerability Scan",
				Kind:             common_go_proto.NoteKind_DISCOVERY,
				Type: &grafeas_go_proto.Note_Discovery{
					Discovery: &discovery_go_proto.Discovery{
						AnalysisKind: common_go_proto.NoteKind_VULNERABILITY,
					},
				},
			},
			// unspecified note will be used as a placeholder for vulnerability occurrences until we come up with a better pattern here
			{
				ShortDescription: "TODO",
				LongDescription:  "TODO",
				Kind:             common_go_proto.NoteKind_NOTE_KIND_UNSPECIFIED,
				Type:             &grafeas_go_proto.Note_Vulnerability{}, // type is required, so this seems like the best option
			},
		},
	}
	res, err := l.rodeClient.RegisterCollector(context.Background(), registerCollectorRequest)
	if err != nil {
		return err
	}

	log.Info("successfully registered with rode")

	l.noteNames = make(map[common_go_proto.NoteKind]string)
	for _, note := range res.Notes {
		l.noteNames[note.Kind] = note.Name
	}

	return nil
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
	log.Debug("received event from harbor")

	var occurrences []*grafeas_go_proto.Occurrence

	if event.Type == harbor.PUSH_ARTIFACT || event.Type == harbor.SCANNING_FAILED {
		occurrences = append(occurrences, l.createDiscoveryOccurrence(event))
	}

	if event.Type == harbor.SCANNING_COMPLETED {
		occurrences = append(occurrences, l.createDiscoveryOccurrence(event))
		report := event.Data.Resources[0].ScanOverview.Report
		if report != nil && report.Summary.Total > 0 {
			scanOccurrences, err := l.createVulnerabilityOccurrences(event)
			if err != nil {
				log.Error("error creating occurrences for vulnerabilities", zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			occurrences = append(occurrences, scanOccurrences...)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

func (l *listener) createDiscoveryOccurrence(event *harbor.Event) *grafeas_go_proto.Occurrence {
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
		NoteName:   l.noteNames[common_go_proto.NoteKind_DISCOVERY],
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
			NoteName:   l.noteNames[common_go_proto.NoteKind_NOTE_KIND_UNSPECIFIED],
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
