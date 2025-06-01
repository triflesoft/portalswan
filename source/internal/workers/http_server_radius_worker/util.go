package http_server_radius_worker

import (
	"encoding/hex"
	"net/http"
	"portalswan/internal/adapters/adapters"
	"strings"
)

type radiusAttribute struct {
	Type  string `json:"type"`
	Value []any  `json:"value"`
}

type radiusRequest map[string]radiusAttribute
type radiusReply map[string]radiusAttribute

type radiusRequestLog struct {
	AcctInputOctets     *int64                     `json:"Acct-Input-Octets,omitempty"`
	AcctInputPackets    *int64                     `json:"Acct-Input-Packets,omitempty"`
	AcctOutputOctets    *int64                     `json:"Acct-Output-Octets,omitempty"`
	AcctOutputPackets   *int64                     `json:"Acct-Output-Packets,omitempty"`
	AcctSessionId       *string                    `json:"Acct-Session-Id,omitempty"`
	AcctSessionTime     *int64                     `json:"Acct-Session-Time,omitempty"`
	AcctStatusType      *string                    `json:"Acct-Status-Type,omitempty"`
	AcctTerminateCause  *string                    `json:"Acct-Terminate-Cause,omitempty"`
	AcctUniqueSessionId *string                    `json:"Acct-Unique-Session-Id,omitempty"`
	CalledStationId     *string                    `json:"Called-Station-Id,omitempty"`
	CallingStationId    *string                    `json:"Calling-Station-Id,omitempty"`
	Class               *string                    `json:"Class,omitempty"`
	EventTimestamp      *string                    `json:"Event-Timestamp,omitempty"`
	FramedIpAddress     *string                    `json:"Framed-IP-Address,omitempty"`
	NasIdentifier       *string                    `json:"NAS-Identifier,omitempty"`
	NasIpAddress        *string                    `json:"NAS-IP-Address,omitempty"`
	NasPort             *int64                     `json:"NAS-Port,omitempty"`
	ServiceType         *string                    `json:"Service-Type,omitempty"`
	UserName            *string                    `json:"User-Name,omitempty"`
	OtherAttributes     map[string]radiusAttribute `json:"OtherAttributes,omitempty"`
}

type radiusReplyLog struct {
	Class                *string                    `json:"Class,omitempty"`
	MsPrimaryDsnServer   *string                    `json:"MS-Primary-DNS-Server,omitempty"`
	MsSecondaryDnsServer *string                    `json:"MS-Secondary-DNS-Server,omitempty"`
	OtherAttributes      map[string]radiusAttribute `json:"OtherAttributes,omitempty"`
}

type radiusRequestReplyLog struct {
	Status  int               `json:"status"`
	Request *radiusRequestLog `json:"request,omitempty"`
	Reply   *radiusReplyLog   `json:"reply,omitempty"`
}

func jsonErrorResponse(w http.ResponseWriter, statusCode int) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
}

func decodeHexText(text string) (string, bool) {
	if (!strings.HasPrefix(text, "0x")) && (!strings.HasPrefix(text, "0X")) {
		return "", false
	}

	text = text[2:]
	data, err := hex.DecodeString(text)

	if err != nil {
		return "", false
	}

	for b := range data {
		if (b <= 32) && (b >= 127) {
			return "", false
		}
	}

	return string(data), true
}

func logRadiusRequestReply(l adapters.LoggingAdapter, stream string, status int, request *radiusRequest, reply *radiusReply) {
	message := radiusRequestReplyLog{
		Status: status,
	}

	if request != nil {
		requestLog := &radiusRequestLog{}
		requestLog.OtherAttributes = map[string]radiusAttribute{}

		for attributeName, attribute := range *request {
			if (attributeName == "EAP-Message") ||
				(attributeName == "Message-Authenticator") ||
				(attributeName == "State") ||
				strings.HasPrefix(attributeName, "NAS-Port-") {
				continue
			}

			if len(attribute.Value) != 1 {
				requestLog.OtherAttributes[attributeName] = attribute
			} else if !strings.HasPrefix(attributeName, "Tmp-") {
				strValue, ok := attribute.Value[0].(string)

				if ok {
					switch attributeName {
					case "Acct-Session-Id":
						requestLog.AcctSessionId = &strValue
					case "Acct-Status-Type":
						requestLog.AcctStatusType = &strValue
					case "Acct-Terminate-Cause":
						requestLog.AcctTerminateCause = &strValue
					case "Acct-Unique-Session-Id":
						requestLog.AcctUniqueSessionId = &strValue
					case "Called-Station-Id":
						requestLog.CalledStationId = &strValue
					case "Calling-Station-Id":
						requestLog.CallingStationId = &strValue
					case "Class":
						clsValue, ok := decodeHexText(strValue)

						if ok {
							requestLog.Class = &clsValue
						} else {
							requestLog.OtherAttributes[attributeName] = attribute
						}
					case "Event-Timestamp":
						requestLog.EventTimestamp = &strValue
					case "Framed-IP-Address":
						requestLog.FramedIpAddress = &strValue
					case "NAS-Identifier":
						requestLog.NasIdentifier = &strValue
					case "NAS-IP-Address":
						requestLog.NasIpAddress = &strValue
					case "Service-Type":
						requestLog.ServiceType = &strValue
					case "User-Name":
						requestLog.UserName = &strValue
					default:
						requestLog.OtherAttributes[attributeName] = attribute
					}
				} else {
					floatValue, ok := attribute.Value[0].(float64)
					intValue := int64(floatValue)

					if ok {
						switch attributeName {
						case "Acct-Input-Octets":
							requestLog.AcctInputOctets = &intValue
						case "Acct-Input-Packets":
							requestLog.AcctInputPackets = &intValue
						case "Acct-Output-Octets":
							requestLog.AcctOutputOctets = &intValue
						case "Acct-Output-Packets":
							requestLog.AcctOutputPackets = &intValue
						case "Acct-Session-Time":
							requestLog.AcctSessionTime = &intValue
						case "NAS-Port":
							requestLog.NasPort = &intValue
						default:
							requestLog.OtherAttributes[attributeName] = attribute
						}
					} else {
						requestLog.OtherAttributes[attributeName] = attribute
					}
				}
			}
		}

		message.Request = requestLog
	}

	if reply != nil {
		replyLog := &radiusReplyLog{}
		replyLog.OtherAttributes = map[string]radiusAttribute{}

		for attributeName, attribute := range *reply {
			if attributeName == "control:NT-Password" {
				continue
			}

			if len(attribute.Value) != 1 {
				replyLog.OtherAttributes[attributeName] = attribute
			} else if !strings.HasPrefix(attributeName, "Tmp-") {
				strValue, ok := attribute.Value[0].(string)

				if ok {
					switch attributeName {
					case "reply:Class":
						replyLog.Class = &strValue
					case "reply:MS-Primary-DNS-Server":
						replyLog.MsPrimaryDsnServer = &strValue
					case "reply:MS-Secondary-DNS-Server":
						replyLog.MsSecondaryDnsServer = &strValue
					default:
						replyLog.OtherAttributes[attributeName] = attribute
					}
				} else {
					replyLog.OtherAttributes[attributeName] = attribute
				}
			}
		}

		message.Reply = replyLog
	}

	l.LogInfoJson(stream, message)
}
