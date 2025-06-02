package vici_client_worker

import (
	"github.com/strongswan/govici/vici"
	"github.com/triflesoft/portalswan/internal/state"
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
