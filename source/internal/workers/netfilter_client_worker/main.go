package netfilter_client_worker

import (
	"time"

	"github.com/puzpuzpuz/xsync"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"portalswan/internal/state"
)

func NetFilterWorker(ws *state.WorkerState) bool {
	go func() {
		log := ws.AppState.LoggingAdapter
		connectionMap := xsync.NewIntegerMapOf[uint32, *connectionTrackingEntry]()

		for {
			conn, err := conntrack.Dial(nil)

			if err != nil {
				log.LogErrorText("Failed to initialize NetFilter connection tracking", "err", err)
				time.Sleep(1 * time.Second)
				continue
			}

			err = conn.SetReadBuffer(8 * 1024 * 1024)

			if err != nil {
				log.LogErrorText("Failed to set read buffer size", "err", err)
			}

			eventChan := make(chan conntrack.Event, 1024)
			errorChan, err := conn.Listen(eventChan, 8, []netfilter.NetlinkGroup{netfilter.GroupCTNew, netfilter.GroupCTDestroy})

			if err != nil {
				log.LogErrorText("Failed to initialize NetFilter connection tracking", "err", err)
				close(eventChan)
				conn.Close()
				time.Sleep(1 * time.Second)
				continue
			}

			log.LogDebugText("NetFilter initalization completed")
			ws.ReportInitCompleted()

			for {
				select {
				case <-ws.QuitChan:
					log.LogDebugText("Terminating NetFilter...")
					conn.Close()
					log.LogDebugText("NetFilter termination completed")
					ws.ReportQuitCompleted()
					return
				case err = <-errorChan:
					log.LogErrorText("NetFilter error", "err", err)
				case event := <-eventChan:
					// Ignore weird and invalid
					if event.Flow == nil {
						continue
					}

					flowID := event.Flow.ID
					flowStatusIsConfirmed := (event.Flow.Status.Value & conntrack.StatusConfirmed) != 0
					flowStatusIsNat := (event.Flow.Status.Value & conntrack.StatusNATMask) != 0

					// Only if looks like a VPN client connection
					if flowStatusIsConfirmed && flowStatusIsNat {
						flowOriginSrcAddr := event.Flow.TupleOrig.IP.SourceAddress
						flowOriginSrcPort := event.Flow.TupleOrig.Proto.SourcePort
						flowOriginDstAddr := event.Flow.TupleOrig.IP.DestinationAddress
						flowOriginDstPort := event.Flow.TupleOrig.Proto.DestinationPort
						flowOriginProto := event.Flow.TupleOrig.Proto.Protocol
						flowReplySrcAddr := event.Flow.TupleReply.IP.SourceAddress
						flowReplySrcPort := event.Flow.TupleReply.Proto.SourcePort
						flowReplyDstAddr := event.Flow.TupleReply.IP.DestinationAddress
						flowReplyDstPort := event.Flow.TupleReply.Proto.DestinationPort
						flowReplyProto := event.Flow.TupleReply.Proto.Protocol

						// Ignore weird and invalid
						if flowOriginProto != flowReplyProto {
							continue
						}

						if (flowOriginDstAddr != flowReplySrcAddr) && (flowOriginSrcAddr != flowReplyDstAddr) {
							continue
						}

						if (flowOriginDstPort != flowReplySrcPort) && (flowOriginSrcPort != flowReplyDstPort) {
							continue
						}

						// Ignore if not a TCP or UDP connection
						if (flowOriginProto != 6) && (flowOriginProto != 17) {
							continue
						}

						// Ignore local DNS
						if (flowOriginProto == 17) && (flowOriginDstPort == 53) && (flowOriginDstAddr.IsPrivate()) {
							continue
						}

						// Only if looks like a VPN client connection
						if !flowOriginSrcAddr.IsPrivate() {
							continue
						}

						switch event.Type {
						case conntrack.EventNew:
							srcAddr := flowOriginSrcAddr.String()
							dstAddr := flowOriginDstAddr.String()
							username := "?"
							connectionState, ok := ws.AppState.GetVpnConnectionState(srcAddr)

							if ok {
								username = connectionState.Username
							}

							entry := &connectionTrackingEntry{
								Username: username,
								Since:    time.Now(),
								Until:    time.Time{},
								Proto:    protoNames[flowOriginProto],
								SrcAddr:  srcAddr,
								SrcPort:  flowOriginSrcPort,
								DstAddr:  dstAddr,
								DstPort:  flowOriginDstPort,
							}

							log.LogDebugText("NetFilter create connection", "id", flowID, "username", entry.Username, "srcAddr", entry.SrcAddr, "srcPort", entry.SrcPort, "dstAddr", entry.DstAddr, "dstPort", entry.DstPort)
							connectionMap.Store(flowID, entry)
						case conntrack.EventDestroy:
							entry, ok := connectionMap.LoadAndDelete(flowID)

							if ok {
								entry.Until = time.Now()
							} else {
								entry = &connectionTrackingEntry{
									Username: "?",
									Since:    time.Time{},
									Until:    time.Now(),
									Proto:    protoNames[flowOriginProto],
									SrcAddr:  flowOriginSrcAddr.String(),
									SrcPort:  flowOriginSrcPort,
									DstAddr:  flowOriginDstAddr.String(),
									DstPort:  flowOriginDstPort,
								}
							}

							log.LogDebugText("NetFilter delete connection", "id", flowID, "username", entry.Username, "srcAddr", entry.SrcAddr, "srcPort", entry.SrcPort, "dstAddr", entry.DstAddr, "dstPort", entry.DstPort)
							go logNetFilterConnection(ws.AppState.LoggingAdapter, entry)
						}
					}
				}
			}
		}
	}()

	return true
}
