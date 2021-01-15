package config

import (
	. "github.com/onsi/gomega"
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
			name:        "Rode host",
			flags:       []string{"--rode-host=bar"},
      expected: &Config{
				Port:  8080,
				Debug: false,
        RodeHost: "bar",
        HarborHost: "http://harbor-harbor-core",
			},
		},
		{
			name:        "Harbor host",
			flags:       []string{"--harbor-host=foo"},
      expected: &Config{
				Port:  8080,
				Debug: false,
        RodeHost: "rode:50051",
        HarborHost: "foo".
			},
		},
	} {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := Build("rode", tc.flags)

			if tc.expectError {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(c).To(BeEquivalentTo(tc.expected))
			}
		})
	}
}
