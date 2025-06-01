package http_server_radius_worker

import (
	"encoding/json"
	"io"
	"net/http"
	"portalswan/internal/state"
)

func (sc *httpServerRadiusContext) internalHttpRadiusHandle(w http.ResponseWriter, r *http.Request) {
	ws := sc.workerState
	log := ws.AppState.LoggingAdapter
	query := r.URL.Query()
	action := query.Get("action")
	requestData, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))

	if err != nil {
		log.LogErrorText("Failed to read request body", "err", err)
		jsonErrorResponse(w, 401)

		return
	}

	request := radiusRequest{}
	err = json.Unmarshal(requestData, &request)

	if err != nil {
		log.LogErrorText("Failed to unmarshal JSON", "err", err)
		jsonErrorResponse(w, 401)

		return
	}

	if action == "authorize" {
		username := ""
		ipAddress := ""

		for attributeName, attribute := range request {
			if (attributeName == "User-Name") && (len(attribute.Value) == 1) {
				username, _ = attribute.Value[0].(string)
			} else if (attributeName == "Calling-Station-Id") && (len(attribute.Value) == 1) {
				ipAddress, _ = attribute.Value[0].(string)
			}
		}

		vpnUser := ws.AppState.IdentityAdapter.SelectVpnUser(username)

		if vpnUser == nil {
			go logRadiusRequestReply(log, "RadiusAuthorize", 401, &request, nil)

			log.LogErrorText("Failed to get VPN user by username", "username", username)
			jsonErrorResponse(w, 401)

			return
		}

		if vpnUser.Class == "" {
			go logRadiusRequestReply(log, "RadiusAuthorize", 401, &request, nil)

			log.LogErrorText("Failed to get VPN user class", "username", username)
			jsonErrorResponse(w, 401)

			return
		}

		ntPassword := ws.AppState.CredentialsAdapter.SelectNtPassword(vpnUser, ipAddress)

		if ntPassword == "" {
			go logRadiusRequestReply(log, "RadiusAuthorize", 401, &request, nil)

			log.LogErrorText("Failed to get VPN user NT password", "username", username)
			jsonErrorResponse(w, 401)

			return
		}

		response := radiusReply{}

		response["control:NT-Password"] = radiusAttribute{
			Type:  "string",
			Value: []any{ntPassword},
		}

		response["reply:Class"] = radiusAttribute{
			Type:  "string",
			Value: []any{vpnUser.Class},
		}

		dnsServers := ws.AppState.GetClientSettings().DnsServers

		if len(dnsServers) >= 1 {
			response["reply:MS-Primary-DNS-Server"] = radiusAttribute{
				Type:  "string",
				Value: []any{dnsServers[0]},
			}
		}

		if len(dnsServers) >= 2 {
			response["reply:MS-Secondary-DNS-Server"] = radiusAttribute{
				Type:  "string",
				Value: []any{dnsServers[1]},
			}
		}

		responseData, err := json.Marshal(response)

		if err != nil {
			go logRadiusRequestReply(log, "RadiusAuthorize", 401, &request, nil)

			log.LogErrorText("Failed to marshal response", "err", err)
			jsonErrorResponse(w, 401)

			return
		}

		go logRadiusRequestReply(log, "RadiusAuthorize", 200, &request, &response)

		log.LogDebugText("Radius authorize", "username", vpnUser.Username, "class", vpnUser.Class)
		w.Header().Del("Content-Type")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(responseData)
	} else {
		username := ""
		framedIpAddress := ""
		statusType := ""
		inputOctets := int64(0)
		inputPackets := int64(0)
		outputOctets := int64(0)
		outputPackets := int64(0)

		for attributeName, attribute := range request {
			if len(attribute.Value) == 1 {
				strValue, ok := attribute.Value[0].(string)

				if ok {
					switch attributeName {
					case "User-Name":
						username = strValue
					case "Framed-IP-Address":
						framedIpAddress = strValue
					case "Acct-Status-Type":
						statusType = strValue
					}
				} else {
					floatValue, ok := attribute.Value[0].(float64)
					intValue := int64(floatValue)

					if ok {
						switch attributeName {
						case "Acct-Input-Octets":
							inputOctets = intValue
						case "Acct-Input-Packets":
							inputPackets = intValue
						case "Acct-Output-Octets":
							outputOctets = intValue
						case "Acct-Output-Packets":
							outputPackets = intValue
						}
					}
				}
			}
		}

		if (username != "") && (framedIpAddress != "") && (statusType != "") {
			switch statusType {
			case "Start":
				log.LogDebugText("Radius create VPN connection", "framedIpAddress", framedIpAddress, "username", username)
				ws.AppState.SetVpnConnectionState(
					framedIpAddress,
					&state.VpnConnectionState{
						Username: username,
					})
			case "Stop":
				connectionState, ok := ws.AppState.DelVpnConnectionState(framedIpAddress)

				if !ok {
					log.LogErrorText("Radius delete VPN connection failed, connection missing", "framedIpAddress", framedIpAddress)
				} else if connectionState.Username != username {
					log.LogErrorText("Radius delete VPN connection failed, username mismatch", "framedIpAddress", framedIpAddress, "username", username)
				} else {
					log.LogDebugText("Radius delete VPN connection", "framedIpAddress", framedIpAddress, "username", username)
				}
			case "Interim-Update":
				if (inputOctets > 0) && (inputPackets > 0) && (outputOctets > 0) && (outputPackets > 0) {
					connectionState, ok := ws.AppState.GetVpnConnectionState(framedIpAddress)

					if !ok {
						log.LogErrorText("Radius update VPN connection failed, unknown connection", "framedIpAddress", framedIpAddress)
					} else {

						if connectionState.Username != username {
							log.LogErrorText("Radius update VPN connection failed, username mismatch", "framedIpAddress", framedIpAddress, "username", username)
							connectionState.Username = username
						}

						connectionState.ClientToServerBytes.Store(inputOctets)
						connectionState.ServerToClientBytes.Store(outputOctets)
						connectionState.ClientToServerPackets.Store(inputPackets)
						connectionState.ServerToClientPackets.Store(outputPackets)

						ws.AppState.SetVpnConnectionState(framedIpAddress, connectionState)
					}
				}
			}

			go logRadiusRequestReply(log, "RadiusAccounting", 204, &request, nil)
		}

		w.Header().Del("Content-Type")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(204)
	}
}

func (sc *httpServerRadiusContext) internalHttpIndexHandler(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
