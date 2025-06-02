package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/triflesoft/portalswan/internal/state"
	"github.com/triflesoft/portalswan/internal/workers/http_server_portal_worker"
	"github.com/triflesoft/portalswan/internal/workers/http_server_radius_worker"
	"github.com/triflesoft/portalswan/internal/workers/netfilter_client_worker"
	"github.com/triflesoft/portalswan/internal/workers/vici_client_worker"
)

func main() {
	appState := state.NewAppState()

	fmt.Println("Starting up...")
	viciClientResult := vici_client_worker.ViciWorker(appState.NewWorkerState())
	netFilterClientResult := netfilter_client_worker.NetFilterWorker(appState.NewWorkerState())
	httpServerRadiusWorker := http_server_radius_worker.HttpServerRadiusWorker(appState.NewWorkerState())
	httpServerPortalWorker := http_server_portal_worker.HttpServerPortalWorker(appState.NewWorkerState())

	if !(viciClientResult || netFilterClientResult || httpServerRadiusWorker || httpServerPortalWorker) {
		fmt.Println("Failed to start up!")
		return
	}
	appState.WaitInitCompleted()

	fmt.Println("Started up successfully.")

	signalChan := make(chan os.Signal, 10)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

for_loop:
	for {
		switch signal := <-signalChan; signal {
		case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			fmt.Printf("Received signal %s", signal.String())
			break for_loop
		}
	}

	fmt.Println()
	fmt.Println("Shutting down...")
	appState.Quit()
	appState.WaitQuitCompleted()
	fmt.Println("Shutted down successfully.")
}
