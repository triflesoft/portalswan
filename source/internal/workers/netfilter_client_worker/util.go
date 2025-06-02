package netfilter_client_worker

import (
	"time"

	"github.com/triflesoft/portalswan/internal/adapters/adapters"
)

const LogChannelName = "NetFilterConnectionTracking"

type connectionTrackingEntry struct {
	Username string    `json:"username"`
	Since    time.Time `json:"since"`
	Until    time.Time `json:"until"`
	Proto    string    `json:"proto"`
	SrcAddr  string    `json:"src_addr"`
	SrcPort  uint16    `json:"src_port"`
	DstAddr  string    `json:"dst_addr"`
	DstPort  uint16    `json:"dst_port"`
}

var protoNames map[uint8]string

func init() {
	protoNames = map[uint8]string{
		1:  "ICMP",
		6:  "TCP",
		17: "UDP",
	}
}

func logNetFilterConnection(l adapters.LoggingAdapter, entry *connectionTrackingEntry) {
	l.LogInfoJson(LogChannelName, entry)
}
