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

var opt_edns0 = dns.OPT{
	Hdr: dns.RR_Header{
		Name:     ".",
		Rrtype:   41,
		Class:    1232,
		Ttl:      0,
		Rdlength: 0,
	},
	Option: []dns.EDNS0{},
}

func isInZones(domain string, zones []config.Zone) bool {
	for _, z := range zones {
		if strings.HasSuffix(domain, z.Name) {
			return true
		}
	}
	return false
}

func getIPv4(device *tpapi.Device, zone *config.Zone, dp *dns_parser) string {
	if zone.GlobalIPv4 {
		return dp.pub_ip.IPv4
	} else {
		return device.IP
	}
}

func getIPv6(device *tpapi.Device, zone *config.Zone) string {
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

func (dp *dns_parser) appendAnswer(answers []dns.RR, name string, rr_type string, rsp string) []dns.RR {
	log.Printf("Query for %s %s\n", name, rr_type)
	line := fmt.Sprintf("%s %d IN %s %s", name, dp.countdown, rr_type, rsp)
	rr, err := dns.NewRR(line)
	if err == nil {
		answers = append(answers, rr)
	} else {
		log.Println(err)
	}
	return answers
}

func (dp *dns_parser) ask(questions []dns.Question) (answers []dns.RR) {
	flushed := false
	for _, q := range questions {
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

		device_name = strings.ToLower(device_name)
		ip_answer_name := q.Name
		_, incache := dp.ReadCache()[device_name]
		if is_ip_query && !incache {
			rec, inCNAMEs := zone.Records.Match(device_name, "CNAME")
			target := rec.Value
			if inCNAMEs {
				if strings.HasSuffix(target, ".") {
					var temp_answers []dns.RR
					if isInZones(target, dp.Conf.Domain.Zones) { // internal cross-zone
						temp_answers = append(answers, dp.ask([]dns.Question{{
							Name:  target,
							Qtype: q.Qtype,
						}})...)
					} else { // external zone
						temp_answers = append(answers, resolve(target, q.Qtype, dp.Conf.Domain.UpstreamServer)...)
					}

					if rec.ChromeSVCBWorkaround {
						for _, a := range temp_answers {
							str := a.String()
							str = strings.Replace(str, target, q.Name, 1)
							new_rr, err := dns.NewRR(str)
							if err != nil {
								log.Printf("failed RR '%s'\n", str)
								continue
							}
							answers = append(answers, new_rr)
						}
					} else {
						answers = dp.appendAnswer(answers, q.Name, "CNAME", target)
						answers = append(answers, temp_answers...)
					}

					continue
				} else { // in-zone/relative CNAME
					if rec.ChromeSVCBWorkaround {
						ip_answer_name = q.Name
					} else {
						answers = dp.appendAnswer(answers, q.Name, "CNAME", target+"."+zone.Name)
						ip_answer_name = device_name + "." + zone.Name
					}
					device_name = target
				}
			} else if !flushed || dp.needFlush {
				log.Printf("%s not found in cache or cache outdated\n", device_name)
				dp.flushCache(true)
				flushed = true
			}
		}

		device, ok := dp.ReadCache()[device_name]
		if !ok && is_ip_query {
			log.Printf("failed to find %s in cache", device_name)
			continue
		}

		var rsp string
		rr_type := dns.Type(q.Qtype).String()

		switch q.Qtype {
		case dns.TypeA:
			rsp = getIPv4(device, zone, dp)
			answers = dp.appendAnswer(answers, ip_answer_name, rr_type, rsp)
		case dns.TypeAAAA:
			rsp = getIPv6(device, zone)
			if rsp == "" {
				continue
			}
			answers = dp.appendAnswer(answers, ip_answer_name, rr_type, rsp)
		default:
			if rec, ok := zone.Records.Match(device_name, rr_type); ok {
				if device, ok := dp.ReadCache()[rec.Template.DeviceName]; ok {
					args := dp.convertArgs(rec.Template.Args, device, zone)
					rsp = fmt.Sprintf(rec.Value, args...)
				} else {
					rsp = rec.Value
				}
				answers = dp.appendAnswer(answers, q.Name, rr_type, rsp)
			}
		}
	}
	return
}

func (dp *dns_parser) convertArgs(args []string, device *tpapi.Device, zone *config.Zone) (out []any) {
	ref := reflect.ValueOf(device)
	for _, arg := range args {
		var f string
		if arg == "IP" {
			f = getIPv4(device, zone, dp)
		} else if arg == "IPv6" {
			f = getIPv6(device, zone)
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
		m.Answer = dp.ask(m.Question)
	}

	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
	}
	if m.RecursionDesired {
		m.RecursionAvailable = true
	}
	m.Extra = append(m.Extra, &opt_edns0)
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
			for name, info := range dp.ReadCache() {
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
