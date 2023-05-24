package parser

import (
	"fmt"
	"log"
	"strings"

	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

func (gdata *dns_parser) parseQuery(m *dns.Msg) {
	flushed := false
	for _, q := range m.Question {
		device_name := strings.Split(q.Name, ".")[0]
		device_name = strings.ToLower(device_name)

		device, ok := gdata.dns_cache[device_name]
		if gdata.needFlush || (!ok && !flushed) {
			log.Printf("%s not found in cache or cache outdated\n", device_name)
			gdata.flushCache(true)
			flushed = true
		}

		device, ok = gdata.dns_cache[device_name]
		if !ok {
			log.Printf("failed to find %s in cache", device_name)
			m.Rcode = dns.RcodeNameError
			break
		}

		var ip string
		var rr_type string
		switch q.Qtype {
		case dns.TypeA:
			rr_type = "A"
			if strings.HasSuffix(q.Name, gdata.pub_zone_name) {
				ip = gdata.pub_ip.IPv4
			} else {
				ip = device.IP
			}
		case dns.TypeAAAA:
			rr_type = "AAAA"
			if strings.HasSuffix(q.Name, gdata.pub_zone_name) {
				ip = device.IPv6
			} else {
				ip, _ = tpapi.Gen_v6("fe80::", device.MAC)
			}

			if ip == "::" {
				log.Printf("skipping AAAA for %s because it doesn't have ipv6", device_name)
				continue
			}
		}

		log.Printf("Query for %s %s\n", q.Name, rr_type)
		line := fmt.Sprintf("%s %d IN %s %s", q.Name, gdata.countdown, rr_type, ip)
		rr, err := dns.NewRR(line)
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
	}
}

func (gdata *dns_parser) HandleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		gdata.parseQuery(m)
	}

	w.WriteMsg(m)
}
