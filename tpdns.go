package main

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

type global_data struct {
	dns_cache     map[string]dualstackips
	tp_conn       tpapi.TPSession
	pub_ip        string
	pub_zone_name string
	ttl           uint
	resetTimer    chan bool
}

type dualstackips struct {
	IPv4 string
	IPv6 string
}

func parseQuery(m *dns.Msg) {
	flushed := false
	for _, q := range m.Question {
		device_name := strings.Split(q.Name, ".")[0]
		device_name = strings.ToLower(device_name)
		ips, ok := gd.dns_cache[device_name]
		if !ok && !flushed {
			log.Printf("%s not found in cache \n", device_name)
			gd.flushCache()
			log.Print("finished flushCache \n")
			flushed = true
		}
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s A\n", q.Name)
			var ip string
			if strings.HasSuffix(q.Name, gd.pub_zone_name) {
				ip = gd.pub_ip
			} else {
				ip = ips.IPv4
			}

			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else {
				m.SetRcode(m, dns.RcodeNameError)
				log.Printf("failed to find %s in cache", device_name)
			}
		case dns.TypeAAAA:
			log.Printf("Query for %s AAAA\n", q.Name)
			ip := ips.IPv6
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else {
				m.SetRcode(m, dns.RcodeNameError)
				log.Printf("failed to find %s in cache", device_name)
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func (gdata *global_data) flushCache() {
	log.Println("started flushCache")
	ds, err := gdata.tp_conn.ApiPost(1, tpapi.Gethostsinfodata, tpapi.Getwaninfodata)
	if err != nil {
		log.Printf("failed to get hosts info: %s\n", err)
	}
	gdata.dns_cache = make(map[string]dualstackips, 0)
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
			gdata.dns_cache[host] = ips
		}
	}
	gdata.pub_ip = ds.Network.WanStatus.IPAddr
	gdata.resetTimer <- true
}

func (gdata *global_data) clearCache() {
	if gdata.ttl == 0 {
		return
	}
	countdown := int(gdata.ttl)

	// Loop until interrupted
	for {
		// Check if the timer has reached zero
		if countdown == 0 {
			gdata.dns_cache = make(map[string]dualstackips, 0)
			log.Println("cache cleared")
			countdown = int(gdata.ttl)
		}
		// Wait for one second
		time.Sleep(time.Second)

		// Check if the timer was reset
		select {
		case <-gdata.resetTimer:
			for len(gdata.resetTimer) > 0 {
				<-gdata.resetTimer
			}
			log.Println("countdown reset")
			countdown = int(gdata.ttl)
		default:
			countdown--
		}
	}
}

var gd global_data

func main() {
	filename := "./config.json"
	conf, err := config.ReadConf(filename)
	if err != nil {
		log.Fatalf("failed to read config file :%s, error: %s\n", filename, err)
	}
	gd.pub_zone_name = conf.Domain.PubZone
	gd.ttl = conf.Server.TTL
	gd.resetTimer = make(chan bool, 10)
	go gd.clearCache()

	if conf.Router.Stok != "" {
		gd.tp_conn = tpapi.TPSessionStok(conf.Router.Url, conf.Router.Stok)
	} else {
		gd.tp_conn, err = tpapi.TPSessionPasswd(conf.Router.Url, conf.Router.Passwd)
		if err != nil {
			log.Fatalf("Failed to connect to router:%s\n", err)
		}
	}

	// attach request handler func
	dns.HandleFunc(conf.Domain.PrivZone, handleDnsRequest)
	dns.HandleFunc(gd.pub_zone_name, handleDnsRequest)

	addr := fmt.Sprintf("%s:%d", conf.Server.IP, conf.Server.Port)
	server := &dns.Server{Addr: addr, Net: "udp"}
	log.Printf("Starting at %s\n", addr)
	err = server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
