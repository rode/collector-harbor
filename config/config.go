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
	"flag"
	"github.com/peterbourgon/ff/v3"
	"github.com/rode/rode/common"
)

type Config struct {
	Port         int
	Debug        bool
	ClientConfig *common.ClientConfig
	HarborConfig *HarborConfig
}

type HarborConfig struct {
	Host     string
	Username string
	Password string
	Insecure bool
}

func Build(name string, args []string) (*Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	c := &Config{
		ClientConfig: common.SetupRodeClientFlags(flags),
		HarborConfig: &HarborConfig{},
	}

	flags.IntVar(&c.Port, "port", 8080, "the port that the harbor collector should listen on")
	flags.BoolVar(&c.Debug, "debug", false, "when set, debug mode will be enabled")

	flags.StringVar(&c.HarborConfig.Host, "harbor-host", "http://harbor-harbor-core", "the host to use when contacting the Harbor API")
	flags.StringVar(&c.HarborConfig.Username, "harbor-username", "", "The username to use to authenticate to Harbor")
	flags.StringVar(&c.HarborConfig.Password, "harbor-password", "", "The password to use to authenticate to Harbor")
	flags.BoolVar(&c.HarborConfig.Insecure, "harbor-insecure", false, "when set, the collector will not verify the TLS certificate for harbor")

	err := ff.Parse(flags, args)
	if err != nil {
		return nil, err
	}

	return c, nil
}
