package parser

import (
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

func (dp *dns_parser) getIPv4(device *tpapi.Device, zone *config.Zone) string {
	if zone.GlobalIPv4 {
		return dp.pub_ip.IPv4
	} else {
		return device.IP
	}
}

func (dp *dns_parser) getIPv6(device *tpapi.Device, zone *config.Zone) string {
	var rsp string
	if zone.GlobalIPv6 {
		if rsp == "::" {
			log.Printf("skipping AAAA for %s because it doesn't have ipv6", device.Hostname)
			return rsp
		}
		rsp = device.IPv6
	} else {
		rsp, _ = tpapi.Gen_v6("fe80::", device.MAC)
	}
	return rsp
}

func (dp *dns_parser) addRsp(m *dns.Msg, name string, rr_type string, rsp string) {
	log.Printf("Query for %s %s\n", name, rr_type)
	line := fmt.Sprintf("%s %d IN %s %s", name, dp.countdown, rr_type, rsp)
	rr, err := dns.NewRR(line)
	if err == nil {
		m.Answer = append(m.Answer, rr)
	}
}

func (dp *dns_parser) parseQuery(m *dns.Msg) {
	flushed := false
	for _, q := range m.Question {
		var device_name string
		var zone *config.Zone
		is_ip_query := (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA)

		for _, z := range dp.Conf.Domain.Zones {
			if strings.HasSuffix(q.Name, z.Name) {
				zone = &z
				device_name = strings.TrimSuffix(q.Name, "."+z.Name)
				break
			}
		}

		if zone == nil {
			continue
		}

		is_default := device_name == zone.Name && zone.DefaultDevice != "" && is_ip_query
		if is_default {
			device_name = zone.DefaultDevice
		}

		var use_name string
		if target, ok := zone.CNAMEs[device_name]; ok && is_ip_query {

			if strings.HasSuffix(target, ".") {
				line := fmt.Sprintf("%s %d IN %s %s", q.Name, dp.countdown, "CNAME", target)
				rr, err := dns.NewRR(line)
				if err == nil {
					m.Answer = append(m.Answer, rr)
				} else {
					log.Println(err)
				}
				m.Answer = append(m.Answer, resolve(target, q.Qtype, dp.Conf.Domain.UpstreamServer)...)
				continue
			} else {
				line := fmt.Sprintf("%s %d IN %s %s", q.Name, dp.countdown, "CNAME", target+"."+zone.Name)
				rr, err := dns.NewRR(line)
				if err == nil {
					m.Answer = append(m.Answer, rr)
				} else {
					log.Println(err)
				}
				device_name = target
				use_name = device_name + "." + zone.Name
			}

		} else {
			use_name = q.Name
		}

		device_name = strings.ToLower(device_name)

		_, ok := dp.dns_cache[device_name]
		if is_ip_query && (dp.needFlush || (!ok && !flushed)) {
			log.Printf("%s not found in cache or cache outdated\n", device_name)
			dp.flushCache(true)
			flushed = true
		}

		device, ok := dp.dns_cache[device_name]
		if !ok && is_ip_query {
			log.Printf("failed to find %s in cache", device_name)
			continue
		}

		var rsp string
		rr_type := dns.Type(q.Qtype).String()

		switch q.Qtype {
		case dns.TypeA:
			rsp = dp.getIPv4(device, zone)
			dp.addRsp(m, use_name, rr_type, rsp)
		case dns.TypeAAAA:
			rsp = dp.getIPv6(device, zone)
			if rsp == "" {
				continue
			}
			dp.addRsp(m, use_name, rr_type, rsp)
		default:
			for _, r := range zone.Records {
				if device_name == r.Name && rr_type == r.Type {
					if r.Template.IsEmpty() {
						rsp = r.Value
					} else if device, ok := dp.dns_cache[r.Template.DeviceName]; ok {
						args := dp.convertArgs(r.Template.Args, device, zone)
						rsp = fmt.Sprintf(r.Value, args...)
					} else {
						continue
					}
					dp.addRsp(m, q.Name, rr_type, rsp)
				}
			}
		}
	}
	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
	}
}

func (dp *dns_parser) convertArgs(args []string, device *tpapi.Device, zone *config.Zone) (out []any) {
	ref := reflect.ValueOf(device)
	for _, arg := range args {
		var f string
		if arg == "IP" {
			f = dp.getIPv4(device, zone)
		} else if arg == "IPv6" {
			f = dp.getIPv6(device, zone)
		} else {
			f = reflect.Indirect(ref).FieldByName(arg).String()
		}
		out = append(out, f)
	}
	return
}

func (dp *dns_parser) HandleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		dp.parseQuery(m)
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
	var zone *config.Zone

	for _, z := range dp.Conf.Domain.Zones {
		if !z.GlobalIPv4 {
			zone = &z
			break
		}
	}
	if zone == nil {
		m.Rcode = dns.RcodeNameError
		return
	}

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
					line := fmt.Sprintf("%s %d IN PTR %s.%s", q.Name, dp.countdown, name, zone.Name)
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
