package parser

import (
	"fmt"
	"log"
	"strings"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

func (gdata *dns_parser) parseQuery(m *dns.Msg) {
	flushed := false
	for _, q := range m.Question {
		var device_name string
		if strings.HasSuffix(q.Name, gdata.Conf.Domain.PubZone.Name) {
			device_name = strings.TrimSuffix(q.Name, "."+gdata.Conf.Domain.PubZone.Name)
		} else if strings.HasSuffix(q.Name, gdata.Conf.Domain.PrivZone.Name) {
			device_name = strings.TrimSuffix(q.Name, "."+gdata.Conf.Domain.PrivZone.Name)
		} else {
			continue
		}

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
			break
		}

		var rsp string
		rr_type := dns.Type(q.Qtype).String()

		switch q.Qtype {
		case dns.TypeA:
			if strings.HasSuffix(q.Name, gdata.Conf.Domain.PubZone.Name) {
				rsp = gdata.pub_ip.IPv4
			} else {
				rsp = device.IP
			}

			log.Printf("Query for %s %s\n", q.Name, rr_type)
			line := fmt.Sprintf("%s %d IN %s %s", q.Name, gdata.countdown, rr_type, rsp)
			rr, err := dns.NewRR(line)
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeAAAA:
			if gdata.Conf.Domain.PrivZone.GlobalIPv6 || strings.HasSuffix(q.Name, gdata.Conf.Domain.PubZone.Name) {
				if rsp == "::" {
					log.Printf("skipping AAAA for %s because it doesn't have ipv6", device_name)
					continue
				}
				rsp = device.IPv6
			} else {
				rsp, _ = tpapi.Gen_v6("fe80::", device.MAC)
			}

			log.Printf("Query for %s %s\n", q.Name, rr_type)
			line := fmt.Sprintf("%s %d IN %s %s", q.Name, gdata.countdown, rr_type, rsp)
			rr, err := dns.NewRR(line)
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		default:
			var records config.Records
			if strings.HasSuffix(q.Name, gdata.Conf.Domain.PubZone.Name) {
				records = gdata.Conf.Domain.PubZone.Records
			} else {
				records = gdata.Conf.Domain.PrivZone.Records
			}
			for _, r := range records {
				if device_name == r.Name && rr_type == r.Type {
					rsp = r.Value
					line := fmt.Sprintf("%s %d IN %s %s", q.Name, gdata.countdown, rr_type, rsp)
					rr, err := dns.NewRR(line)
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			}

		}
	}
	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
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
					line := fmt.Sprintf("%s %d IN PTR %s.%s", q.Name, dp.countdown, name, dp.Conf.Domain.PrivZone.Name)
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

			return
		}
	}
	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
	}
}

func reverse(a []string) []string {
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
}
