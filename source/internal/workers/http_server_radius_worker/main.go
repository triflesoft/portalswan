package http_server_radius_worker

import (
	"context"
	"net/http"
	"portalswan/internal/state"
	"sync/atomic"
	"time"
)

type httpServerRadiusContext struct {
	workerState *state.WorkerState
}

func HttpServerRadiusWorker(ws *state.WorkerState) bool {
	log := ws.AppState.LoggingAdapter

	httpServerRadiusContext := httpServerRadiusContext{
		workerState: ws,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/radius/", httpServerRadiusContext.internalHttpRadiusHandle)
	mux.HandleFunc("/", httpServerRadiusContext.internalHttpIndexHandler)

	httpServer := &http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: mux,
	}

	isRunning := atomic.Bool{}
	isRunning.Store(true)

	go func() {
		for {
			if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
				isRunning.Store(false)
				log.LogErrorText("Failed to start HTTP server", "err", err)
			}

			time.Sleep(time.Second)
		}
	}()

	go func() {
		for {
			select {
			case <-ws.QuitChan:
				log.LogDebugText("Terminating Radius HTTP...")

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				if err := httpServer.Shutdown(ctx); err != nil {
					log.LogErrorText("Failed to stop HTTP server", "err", err)
				}

				log.LogDebugText("Radius HTTP termination completed")
				ws.ReportQuitCompleted()
				return
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	log.LogDebugText("Radius HTTP initalization completed")
	ws.ReportInitCompleted()

	return isRunning.Load()
}
