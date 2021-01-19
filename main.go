package main

import (
	"context"
	"fmt"
	"github.com/rode/collector-harbor/config"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/liatrio/rode-api/proto/v1alpha1"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/rode/collector-harbor/listener"
)

var (
	debug    bool
	port     int
	rodeHost string
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

	conn, err := grpc.Dial(conf.RodeHost, grpc.WithInsecure(), grpc.WithBlock())
	defer conn.Close()
	if err != nil {
		logger.Fatal("failed to establish grpc connection to Rode API", zap.NamedError("error", err))
	}

	rodeClient := pb.NewRodeClient(conn)

	l := listener.NewListener(logger.Named("listener"), rodeClient)

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/event", l.ProcessEvent)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "I'm healthy") })
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		err = server.ListenAndServe()
		if err != nil {
			logger.Fatal("could not start http server...", zap.NamedError("error", err))
		}
	}()

	logger.Info("listening for Harbor events", zap.String("host", server.Addr))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	terminationSignal := <-sig
	logger.Info("shutting down...", zap.String("termination signal", terminationSignal.String()))

	err = server.Shutdown(context.Background())
	if err != nil {
		logger.Fatal("could not shutdown http server...", zap.NamedError("error", err))
	}
}

func createLogger(debug bool) (*zap.Logger, error) {
	if debug {
		return zap.NewDevelopment()
	}

	return zap.NewProduction()
}
