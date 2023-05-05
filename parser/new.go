package parser

import (
	"sync"

	"github.com/deorth-kku/tpdns/tpapi"
)

type dns_parser struct {
	dns_cache         map[string]dualstackips
	tp_conn           tpapi.TPSession
	pub_ip            string
	pub_zone_name     string
	ttl               uint
	countdown         uint
	resetTimer        chan bool
	eventReconnect    chan dualstackips
	eventDeviceOnline chan tpapi.Device
	onReconnect       func(ipv4 string, ipv6prefix string)
	onDeviceOnline    func(tpapi.Device)
	needFlush         bool
	cache_lock        sync.Mutex
}

type dualstackips struct {
	IPv4 string
	IPv6 string
}

func Parser(pub_zone string, ttl uint, conn tpapi.TPSession) *dns_parser {
	gd := &dns_parser{
		tp_conn:           conn,
		pub_zone_name:     pub_zone,
		ttl:               ttl,
		resetTimer:        make(chan bool, 10),
		eventReconnect:    make(chan dualstackips, 2),
		eventDeviceOnline: make(chan tpapi.Device, 20),
		needFlush:         true,
	}
	go gd.ttlCountdown()
	go gd.runEventLoop()
	return gd
}
