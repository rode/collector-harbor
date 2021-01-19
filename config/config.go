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

	flags.IntVar(&c.Port, "port", 8080, "the port that the harbor collector should listen on")
	flags.BoolVar(&c.Debug, "debug", false, "when set, debug mode will be enabled")
	flags.StringVar(&c.RodeHost, "rode-host", "rode:50051", "the host to use to connect to rode")
	flags.StringVar(&c.HarborConfig.Host, "harbor-host", "http://harbor-harbor-core", "the host to use when contacting the Harbor API")
	flags.StringVar(&c.HarborConfig.Username, "harbor-username", "", "The username to use to authenticate to Harbor")
	flags.StringVar(&c.HarborConfig.Password, "harbor-password", "", "The password to use to authenticate to Harbor")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}
