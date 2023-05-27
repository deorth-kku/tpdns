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
			if strings.HasSuffix(q.Name, gdata.Conf.Domain.PubZone) {
				ip = gdata.pub_ip.IPv4
			} else {
				ip = device.IP
			}
		case dns.TypeAAAA:
			rr_type = "AAAA"
			if gdata.Conf.Domain.PrivZoneGlobalIPv6 || strings.HasSuffix(q.Name, gdata.Conf.Domain.PubZone) {
				if ip == "::" {
					log.Printf("skipping AAAA for %s because it doesn't have ipv6", device_name)
					continue
				}
				ip = device.IPv6
			} else {
				ip, _ = tpapi.Gen_v6("fe80::", device.MAC)
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

func (dp *dns_parser) HandlePtrRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		dp.parsePtrQuery(m)
	}

	w.WriteMsg(m)
}

const PtrSuffix = "in-addr.arpa."

func (dp *dns_parser) parsePtrQuery(m *dns.Msg) {
	for _, q := range m.Question {
		if !strings.HasSuffix(q.Name, PtrSuffix) {
			log.Printf("unsupported name for PTR: %s", q.Name)
			continue
		}
		m.RecursionAvailable = true
		reverse_ip := strings.TrimSuffix(q.Name, PtrSuffix)
		reverse_ip_slice := strings.Split(reverse_ip, ".")
		if len(reverse_ip_slice) != 5 {
			log.Printf("invaild PTR request %s", q.Name)
		}
		ip := strings.Join(reverse(reverse_ip_slice[0:4]), ".")
		switch q.Qtype {
		case dns.TypePTR:
			for name, info := range dp.dns_cache {
				if ip == info.IP {
					line := fmt.Sprintf("%s %d IN PTR %s.%s", q.Name, dp.countdown, name, dp.Conf.Domain.PrivZone)
					rr, err := dns.NewRR(line)
					if err == nil {
						m.Answer = append(m.Answer, rr)
					} else {
						log.Panic(err)
					}
					return
				}
			}
			log.Printf("failed to find %s in cache", ip)
			m.Rcode = dns.RcodeNameError
			return
		}
	}
}

func reverse(a []string) []string {
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
}
