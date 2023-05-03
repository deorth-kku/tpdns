package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/parser"
	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

func main() {
	var filename string
	var logfile string
	var h bool
	flag.StringVar(&filename, "c", "./config.json", "Set config file")
	flag.StringVar(&logfile, "l", "-", "Set log file")
	flag.BoolVar(&h, "h", false, "Show help")
	flag.Parse()

	if h {
		flag.Usage()
		os.Exit(0)
	}
	if logfile != "-" {
		file, err := os.OpenFile(logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(file)
		defer file.Close()
	}

	conf, err := config.ReadConf(filename)
	if err != nil {
		log.Fatalf("failed to read config file : %s, error: %s\n", filename, err)
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
	dp.SetOnDeviceOnline(func(dev tpapi.Device) {
		fmt.Printf("new device online %s\n", dev.Hostname)
	})
	dp.SetOnReconnect(func(ipv4 string, ipv6 string) {
		fmt.Printf("reconnected with ipv4: %s, ipv6: %s\n", ipv4, ipv6)
	})

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
