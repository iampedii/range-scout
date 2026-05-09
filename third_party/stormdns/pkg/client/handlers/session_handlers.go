// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package handlers

import (
	"net"

	Enums "range-scout/third_party/stormdns/internal/enums"
	VpnProto "range-scout/third_party/stormdns/internal/vpnproto"
)

func init() {
	RegisterHandler(Enums.PACKET_SESSION_BUSY, handleSessionBusy)
	RegisterHandler(Enums.PACKET_ERROR_DROP, handleErrorDrop)
}

func handleSessionBusy(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleSessionBusy()
}

func handleErrorDrop(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleErrorDrop(packet)
}
