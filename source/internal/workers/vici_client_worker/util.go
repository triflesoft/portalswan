package vici_client_worker

import (
	"portalswan/internal/state"

	"github.com/strongswan/govici/vici"
)

const LogChannelName = "StrongSwanVici"

func logViciMessage(ws *state.WorkerState, message *vici.Message) {
	log := ws.AppState.LoggingAdapter
	messageMap := map[string]any{}

	for _, k := range message.Keys() {
		messageMap[k] = message.Get(k)
	}

	log.LogInfoJson(LogChannelName, messageMap)
}
