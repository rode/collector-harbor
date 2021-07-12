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

package config

import (
	. "github.com/onsi/gomega"
	"github.com/rode/rode/common"
	"testing"
)

func TestConfig(t *testing.T) {
	Expect := NewGomegaWithT(t).Expect

	for _, tc := range []struct {
		name        string
		flags       []string
		expected    *Config
		expectError bool
	}{
		{
			name:  "defaults",
			flags: []string{},
			expected: &Config{
				Port:  8080,
				Debug: false,
				ClientConfig: &common.ClientConfig{
					Rode: &common.RodeClientConfig{
						Host: "rode:50051",
					},
					OIDCAuth:  &common.OIDCAuthConfig{},
					BasicAuth: &common.BasicAuthConfig{},
				},
				HarborConfig: &HarborConfig{
					Host: "http://harbor-harbor-core",
				},
			},
		},
		{
			name:        "bad port",
			flags:       []string{"--port=foo"},
			expectError: true,
		},
		{
			name:        "bad debug",
			flags:       []string{"--debug=bar"},
			expectError: true,
		},
		{
			name:  "Rode host",
			flags: []string{"--rode-host=bar"},
			expected: &Config{
				Port:  8080,
				Debug: false,
				ClientConfig: &common.ClientConfig{
					Rode: &common.RodeClientConfig{
						Host: "bar",
					},
					OIDCAuth:  &common.OIDCAuthConfig{},
					BasicAuth: &common.BasicAuthConfig{},
				},
				HarborConfig: &HarborConfig{
					Host: "http://harbor-harbor-core",
				},
			},
		},
		{
			name:  "Harbor host",
			flags: []string{"--harbor-host=foo", "--harbor-username=bar", "--harbor-password=baz", "--harbor-insecure"},
			expected: &Config{
				Port:  8080,
				Debug: false,
				ClientConfig: &common.ClientConfig{
					Rode: &common.RodeClientConfig{
						Host: "rode:50051",
					},
					OIDCAuth:  &common.OIDCAuthConfig{},
					BasicAuth: &common.BasicAuthConfig{},
				},
				HarborConfig: &HarborConfig{
					Host:     "foo",
					Username: "bar",
					Password: "baz",
					Insecure: true,
				},
			},
		},
	} {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := Build("rode-collector-harbor", tc.flags)

			if tc.expectError {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(c).To(BeEquivalentTo(tc.expected))
			}
		})
	}
}
