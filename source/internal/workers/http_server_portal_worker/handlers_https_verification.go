package http_server_portal_worker

import (
	"encoding/json"
	"net"
	"net/http"
	"time"
)

type verificationReply struct {
	Timestamp             int64  `json:"Timestamp"`
	IpAddress             string `json:"IpAddress"`
	Username              string `json:"Username"`
	ClientToServerBytes   int64  `json:"ClientToServerBytes"`
	ServerToClientBytes   int64  `json:"ServerToClientBytes"`
	ClientToServerPackets int64  `json:"ClientToServerPackets"`
	ServerToClientPackets int64  `json:"ServerToClientPackets"`
}

func (sc *httpServerPortalContext) publicHttpsVerificationHandler(w http.ResponseWriter, r *http.Request) {
	ws := sc.workerState

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	connectionState, ok := ws.AppState.GetVpnConnectionState(remoteAddr)

	if !ok {
		logHttpRequest(ws, r, http.StatusInternalServerError, err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(verificationReply{
		Timestamp:             time.Now().UnixMilli(),
		Username:              connectionState.Username,
		IpAddress:             remoteAddr,
		ClientToServerBytes:   connectionState.ClientToServerBytes.Load(),
		ServerToClientBytes:   connectionState.ServerToClientBytes.Load(),
		ClientToServerPackets: connectionState.ClientToServerPackets.Load(),
		ServerToClientPackets: connectionState.ServerToClientPackets.Load(),
	})

	if err != nil {
		logHttpRequest(ws, r, http.StatusInternalServerError, err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}
