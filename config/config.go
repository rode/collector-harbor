package config

import (
	"flag"
)

type Config struct {
	Port       int
	Debug      bool
	RodeHost   string
	HarborHost string
	/* Need to add creds back */
}

func Build(name string, args []string) (*Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	c := &Config{}

	flag.IntVar(&c.Port, "port", 8080, "the port that the harbor collector should listen on")
	flag.BoolVar(&c.Debug, "debug", false, "when set, debug mode will be enabled")
	flag.StringVar(&c.RodeHost, "rode-host", "rode:50051", "the host to use to connect to rode")
	flag.StringVar(&c.HarborHost, "harbor-host", "http://harbor-harbor-core", "the host to use when contacting the Harbor API")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}
