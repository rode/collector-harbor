package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/rode/collector-harbor/harbor"
	"google.golang.org/grpc/credentials"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/liatrio/rode-api/proto/v1alpha1"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/rode/collector-harbor/config"
	"github.com/rode/collector-harbor/listener"
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

	dialOptions := []grpc.DialOption{
		grpc.WithBlock(),
	}
	if conf.RodeConfig.Insecure {
		dialOptions = append(dialOptions, grpc.WithInsecure())
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	conn, err := grpc.DialContext(ctx, conf.RodeConfig.Host, dialOptions...)
	if err != nil {
		logger.Fatal("failed to establish grpc connection to Rode", zap.Error(err))
	}
	defer conn.Close()

	rodeClient := pb.NewRodeClient(conn)
	harborClient := harbor.NewClient(conf.HarborConfig)

	l := listener.NewListener(logger.Named("listener"), rodeClient, conf, harborClient)

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/event", l.ProcessEvent)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "I'm healthy") })
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", conf.Port),
		Handler: mux,
	}

	go func() {
		err = server.ListenAndServe()
		if err != nil {
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
