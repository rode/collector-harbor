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

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/rode/collector-harbor/config"
	"github.com/rode/collector-harbor/harbor"
	"github.com/rode/collector-harbor/listener"
	"github.com/rode/rode/common"
	"go.uber.org/zap"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	conf, err := config.Build(os.Args[0], os.Args[1:])
	if err != nil {
		log.Fatalf("error parsing flags: %v", err)
	}

	logger, err := createLogger(conf.Debug)
	if err != nil {
		log.Fatalf("failed to create logger: %v", err)
	}

	rodeClient, err := common.NewRodeClient(conf.ClientConfig)
	if err != nil {
		logger.Fatal("could not create rode client", zap.Error(err))
	}

	harborClient := harbor.NewClient(conf.HarborConfig)

	l := listener.NewListener(logger.Named("listener"), rodeClient, harborClient)

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/event", l.ProcessEvent)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "I'm healthy") })
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", conf.Port),
		Handler: mux,
	}

	go func() {
		err = server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("could not start http server...", zap.Error(err))
		}
	}()

	logger.Info("listening for Harbor events", zap.String("host", server.Addr))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	terminationSignal := <-sig
	logger.Info("shutting down...", zap.String("termination signal", terminationSignal.String()))

	err = server.Shutdown(context.Background())
	if err != nil {
		logger.Fatal("could not shutdown http server...", zap.Error(err))
	}
}

func createLogger(debug bool) (*zap.Logger, error) {
	if debug {
		return zap.NewDevelopment()
	}

	return zap.NewProduction()
}
