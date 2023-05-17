package parser

import "github.com/deorth-kku/tpdns/tpapi"

func (dp *dns_parser) runEventLoop() {
	for {
		select {
		case ips := <-dp.eventReconnect:
			if dp.onReconnect != nil {
				dp.onReconnect(ips.IPv4, ips.IPv6)
			}
		case dev := <-dp.eventDeviceOnline:
			if dp.onDeviceOnline != nil {
				dp.onDeviceOnline(dev)
			}
		}
	}
}

func (dp *dns_parser) SetOnReconnect(orf func(ipv4 string, ipv6prefix string)) {
	dp.onReconnect = orf
	dp.onReconnect(dp.pub_ip.IPv4, dp.pub_ip.IPv6)
}

func (dp *dns_parser) SetOnDeviceOnline(odof func(tpapi.Device)) {
	dp.onDeviceOnline = odof
}
