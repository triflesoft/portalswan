package vici_client_worker

import (
	"time"

	"github.com/strongswan/govici/vici"
	"github.com/triflesoft/portalswan/internal/state"
)

func ViciWorker(ws *state.WorkerState) bool {
	go func() {
		log := ws.AppState.LoggingAdapter

		for {
			session, err := vici.NewSession(vici.WithAddr("unix", "/var/run/strongswan/charon.vici"))

			if err != nil {
				log.LogErrorText("Failed to connect to StrongSwan", "err", err)
				time.Sleep(1 * time.Second)
				continue
			}

			versionMessage, err := session.CommandRequest("version", nil)

			if err != nil {
				log.LogErrorText("Failed to query version", "err", err)
				session.Close()
				time.Sleep(1 * time.Second)
				continue
			}

			logViciMessage(ws, versionMessage)

			log.LogDebugText("VICI initalization completed")
			ws.ReportInitCompleted()

			eventChan := make(chan vici.Event, 256)
			session.NotifyEvents(eventChan)

			if err := session.Subscribe("log", "ike-updown", "ike-update", "child-updown"); err != nil {
				log.LogErrorText("Failed to subscribe", "err", err)
				close(eventChan)
				time.Sleep(1 * time.Second)
				continue
			}

			for {
				select {
				case <-ws.QuitChan:
					log.LogDebugText("Terminating VICI...")
					session.Close()
					log.LogDebugText("VICI termination completed")
					ws.ReportQuitCompleted()
					return
				case event := <-eventChan:
					go logViciMessage(ws, event.Message)
				}
			}
		}

	}()

	return true
}
