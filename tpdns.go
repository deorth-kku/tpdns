package main

import (
	"fmt"
	"log"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/parser"
	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

func main() {
	filename := "./config.json"
	conf, err := config.ReadConf(filename)
	if err != nil {
		log.Fatalf("failed to read config file :%s, error: %s\n", filename, err)
	}
	var c tpapi.TPSession
	if conf.Router.Stok != "" {
		c = tpapi.TPSessionStok(conf.Router.Url, conf.Router.Stok)
	} else {
		c, err = tpapi.TPSessionPasswd(conf.Router.Url, conf.Router.Passwd)
		if err != nil {
			log.Panicf("Failed to connect to router:%s\n", err)
		}
	}
	dp := parser.Parser(conf.Domain.PubZone, conf.Domain.TTL, c)

	// attach request handler func
	dns.HandleFunc(conf.Domain.PrivZone, dp.HandleDnsRequest)
	dns.HandleFunc(conf.Domain.PubZone, dp.HandleDnsRequest)

	addr := fmt.Sprintf("%s:%d", conf.Server.IP, conf.Server.Port)
	server := &dns.Server{Addr: addr, Net: "udp"}
	log.Printf("Starting at %s\n", addr)
	err = server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
