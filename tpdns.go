package main

import (
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

var dns_cache = map[string]dualstackips{}

type dualstackips struct {
	IPv4 string
	IPv6 string
}

var pub_zone_name string
var pub_ip = ""
var tp_conn tpapi.TPSession

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		device_name := strings.Split(q.Name, ".")[0]
		device_name = strings.ToLower(device_name)
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s A\n", q.Name)
			var ip string
			if strings.HasSuffix(q.Name, pub_zone_name) {
				ip = pub_ip
			} else {
				ip = dns_cache[device_name].IPv4
			}

			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else {
				log.Printf("failed to find %s in cache", device_name)
			}
		case dns.TypeAAAA:
			log.Printf("Query for %s AAAA\n", q.Name)
			ip := dns_cache[device_name].IPv6
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else {
				log.Printf("failed to find %s in cache", device_name)
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	flushCache()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func flushCache() {
	ds, err := tp_conn.ApiPost(1, tpapi.Gethostsinfodata, tpapi.Getwaninfodata)
	if err != nil {
		log.Printf("failed to get hosts info: %s\n", err)
	}
	for _, line := range ds.HostsInfo.HostInfo {
		for _, info := range line {
			host, err := url.QueryUnescape(info.Hostname)
			host = strings.ToLower(host)
			host = strings.ReplaceAll(host, " ", "-")
			if err != nil {
				log.Printf("failed to unescape hostname: %s", info.Hostname)
			}
			if host == "" {
				continue
			}
			ips := dualstackips{info.IP, info.IPv6}
			dns_cache[host] = ips
		}
	}
	pub_ip = ds.Network.WanStatus.IPAddr

}

func main() {
	filename := "./config.json"
	conf, err := config.ReadConf(filename)
	if err != nil {
		log.Fatalf("failed to read config file :%s, error: %s\n", filename, err)
	}
	pub_zone_name = conf.Domain.PubZone
	if conf.Router.Stok != "" {
		tp_conn = tpapi.TPSessionStok(conf.Router.Url, conf.Router.Stok)
	} else {
		tp_conn, err = tpapi.TPSessionPasswd(conf.Router.Url, conf.Router.Passwd)
		if err != nil {
			log.Fatalf("Failed to connect to router:%s\n", err)
		}
	}

	// attach request handler func
	dns.HandleFunc(conf.Domain.PrivZone, handleDnsRequest)
	dns.HandleFunc(pub_zone_name, handleDnsRequest)

	addr := fmt.Sprintf("%s:%d", conf.Server.IP, conf.Server.Port)
	server := &dns.Server{Addr: addr, Net: "udp"}
	log.Printf("Starting at %s\n", addr)
	err = server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
