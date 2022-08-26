package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	r := newRuleManager()
	log.Println("starting")
	err := r.start(ctx)
	if err != nil {
		log.Fatalf("error starting: %v", err)
	}
	return

	<-ctx.Done()
	log.Println("shutting down")
	r.stop()
}
