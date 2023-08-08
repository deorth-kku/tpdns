package parser

import (
	"sync"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/tpapi"
)

type dns_parser struct {
	Conf      *config.TpdnsConfig
	TpSession *tpapi.TPSession

	dns_cache         map[string]*tpapi.Device
	pub_ip            dualstackips
	countdown         uint
	resetTimer        chan bool
	eventReconnect    chan dualstackips
	eventDeviceOnline chan *tpapi.Device
	onReconnect       func(ipv4 string, ipv6prefix string)
	onDeviceOnline    func(*tpapi.Device)
	needFlush         bool
	cache_lock        sync.Mutex
}

type dualstackips struct {
	IPv4 string
	IPv6 string
}

func Parser(conf *config.TpdnsConfig, conn *tpapi.TPSession) *dns_parser {
	gd := &dns_parser{
		Conf:              conf,
		TpSession:         conn,
		resetTimer:        make(chan bool, 10),
		eventReconnect:    make(chan dualstackips, 2),
		eventDeviceOnline: make(chan *tpapi.Device, 20),
	}
	gd.flushCache(false)
	go gd.ttlCountdown()
	go gd.runEventLoop()
	return gd
}
