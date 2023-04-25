package parser

import "github.com/deorth-kku/tpdns/tpapi"

type dns_parser struct {
	dns_cache     map[string]dualstackips
	tp_conn       tpapi.TPSession
	pub_ip        string
	pub_zone_name string
	ttl           uint
	countdown     uint
	resetTimer    chan bool
}

type dualstackips struct {
	IPv4 string
	IPv6 string
}

func Parser(pub_zone string, ttl uint, conn tpapi.TPSession) *dns_parser {
	gd := &dns_parser{
		tp_conn:       conn,
		pub_zone_name: pub_zone,
		ttl:           ttl,
		resetTimer:    make(chan bool, 10),
	}
	go gd.clearCache()
	return gd
}
