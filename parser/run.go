package parser

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

func (gdata *dns_parser) parseQuery(m *dns.Msg) {
	flushed := false
	for _, q := range m.Question {
		device_name := strings.Split(q.Name, ".")[0]
		device_name = strings.ToLower(device_name)

		ips, ok := gdata.dns_cache[device_name]
		if !ok && !flushed {
			log.Printf("%s not found in cache \n", device_name)
			gdata.flushCache()
			log.Print("finished flushCache \n")
			flushed = true
		}

		ips, ok = gdata.dns_cache[device_name]
		if !ok {
			log.Printf("failed to find %s in cache", device_name)
			m.Rcode = dns.RcodeNameError
			break
		}
		var line string
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s A\n", q.Name)
			var ip string
			if strings.HasSuffix(q.Name, gdata.pub_zone_name) {
				ip = gdata.pub_ip
			} else {
				ip = ips.IPv4
			}
			line = fmt.Sprintf("%s A %s", q.Name, ip)
		case dns.TypeAAAA:
			log.Printf("Query for %s AAAA\n", q.Name)
			ip := ips.IPv6
			line = fmt.Sprintf("%s %d IN AAAA %s", q.Name, gdata.countdown, ip)
		}

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
