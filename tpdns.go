package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/dynv6"
	"github.com/deorth-kku/tpdns/parser"
	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

func update_rules_for_dev(dev tpapi.Device, c tpapi.TPSession, conf_rules []config.DeviceFwRules, onconnect bool) {
	devname, err := url.QueryUnescape(dev.Hostname)
	if err != nil {
		log.Printf("not unescapable device name %s\n", dev.Hostname)
		devname = dev.Hostname
	}
	if !onconnect {
		log.Printf("new device online %s\n", devname)
	}

	for _, conf_dev := range conf_rules {
		match_mac := conf_dev.Mac == "" || dev.MAC == conf_dev.Mac
		match_name := conf_dev.Name == "" || devname == conf_dev.Name

		if match_mac && match_name {
			existed_rules, err := c.Getfwrules(1)
			if err != nil {
				log.Printf("failed to Getfwrules: %s\n", err)
				return
			}
			for _, conf_rule := range conf_dev.Rules {
				name, rule, ok := existed_rules.Search(conf_rule.Proto, conf_rule.Port)
				if !ok {
					err = c.AddFwRule(1, conf_rule.Port, dev.IP, dev.IPv6, conf_rule.Proto)
					if err != nil {
						log.Printf("failed to add new rule %d %s, %s", conf_rule.Port, conf_rule.Proto, err)
					}
					continue
				}
				if rule.DestIP == dev.IP && rule.DestIP6 == dev.IPv6 {
					continue
				}
				err = c.DelFwRule(1, name)
				if err != nil {
					log.Printf("failed to delete old rule %d %s, %s", conf_rule.Port, conf_rule.Proto, err)
				} else {
					log.Printf("deleted old rule %d %s", conf_rule.Port, conf_rule.Proto)
				}
				err = c.AddFwRule(1, conf_rule.Port, dev.IP, dev.IPv6, conf_rule.Proto)
				if err != nil {
					log.Printf("failed to add new rule %d %s, %s", conf_rule.Port, conf_rule.Proto, err)
				}
			}

		}
	}
}

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
		log.Panicf("failed to read config file : %s, error: %s\n", filename, err)
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
	c.SetGenerateIPv6(conf.Domain.GenIPv6...)

	dynv6_enabled := conf.Dynv6.Token != "" && conf.Dynv6.Zone != ""

	var d dynv6.Dynv6Zone
	if dynv6_enabled {
		d, err = dynv6.New(conf.Dynv6.Token, conf.Dynv6.Zone)
		if err != nil {
			log.Panicf("failed to connect to dynv6: %s\n", err)
		}
	}

	dp := parser.Parser(conf.Domain.PubZone, conf.Domain.TTL, c)
	dp.SetOnReconnect(func(ipv4 string, ipv6 string) {
		log.Printf("reconnected with ipv4: %s, ipv6: %s\n", ipv4, ipv6)
		if dynv6_enabled {
			_, err := d.Update(ipv4, ipv6)
			if err != nil {
				log.Printf("failed to update dynv6 zone, %s", err)
			}
		}
		devs, err := c.Gethostsinfo(1)
		if err != nil {
			log.Printf("failed to Gethostsinfo: %s\n", err)
			return
		}
		for _, dev := range devs {
			update_rules_for_dev(dev, c, conf.Fwrules, true)
		}

	})
	dp.SetOnDeviceOnline(func(dev tpapi.Device) {
		update_rules_for_dev(dev, c, conf.Fwrules, false)
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
