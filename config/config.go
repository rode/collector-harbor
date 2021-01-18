package config

import (
	"flag"
)

type Config struct {
	Port         int
	Debug        bool
	RodeHost     string
  HarborConfig *HarborConfig
}

type HarborConfig struct {
	Host     string
  Username string
  Password string
}

func Build(name string, args []string) (*Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

  c := &Config{
    HarborConfig: &HarborConfig{},
  }

	flag.IntVar(&c.Port, "port", 8080, "the port that the harbor collector should listen on")
	flag.BoolVar(&c.Debug, "debug", false, "when set, debug mode will be enabled")
	flag.StringVar(&c.RodeHost, "rode-host", "rode:50051", "the host to use to connect to rode")
	flag.StringVar(&c.HarborConfig.Host, "harbor-host", "http://harbor-harbor-core", "the host to use when contacting the Harbor API")
	flag.StringVar(&c.HarborConfig.Username, "harbor-username", "", "The username to use to authenticate to Harbor")
	flag.StringVar(&c.HarborConfig.Password, "harbor-password", "", "The password to use to authenticate to Harbor")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}
