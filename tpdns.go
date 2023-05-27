package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/dynv6"
	"github.com/deorth-kku/tpdns/parser"
	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

func update_rules_for_dev(dev tpapi.Device, c *tpapi.TPSession, conf_rules []config.DeviceFwRules, onconnect bool) {
	devname, err := url.QueryUnescape(dev.Hostname)
	if err != nil {
		log.Printf("not unescapable device name %s\n", dev.Hostname)
		devname = dev.Hostname
	}
	if onconnect {
		log.Printf("init device on connect: %s\n", devname)
	} else {
		log.Printf("new device online: %s\n", devname)
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
						log.Printf("failed to add new rule %d %s, %s\n", conf_rule.Port, conf_rule.Proto, err)
					}
					continue
				}
				if rule.DestIP == dev.IP && rule.DestIP6 == dev.IPv6 {
					continue
				}
				err = c.DelFwRule(1, name)
				if err != nil {
					log.Printf("failed to delete old rule %d %s, %s\n", conf_rule.Port, conf_rule.Proto, err)
				} else {
					log.Printf("deleted old rule %d %s\n", conf_rule.Port, conf_rule.Proto)
				}
				err = c.AddFwRule(1, conf_rule.Port, dev.IP, dev.IPv6, conf_rule.Proto)
				if err != nil {
					log.Printf("failed to add new rule %d %s, %s\n", conf_rule.Port, conf_rule.Proto, err)
				}
			}

		}
	}
}

func updateSPF(name string, ipv4 string, ipv6prefix string, zone *dynv6.Zone) {
	rs, err := zone.GetRecords()
	if err != nil {
		log.Printf("failed to get records for zone %d\n", zone.ID)
		return
	}
	new_data := fmt.Sprintf("v=spf1 ip4:%s ip6:%s -all", ipv4, ipv6prefix)
	req := dynv6.RecordInfo{Name: name, Data: new_data, Type: "TXT"}
	for _, r := range rs {
		if r.Type == "TXT" && r.Name == name && strings.HasPrefix(r.Data, "v=spf1") {
			_, err := r.Update(req)
			if err != nil {
				log.Printf("failed to update spf record, %s\n", err)
			}
			return
		}
	}
	log.Println("no spf found, adding")
	_, err = zone.AddRecord(req)
	if err != nil {
		log.Printf("failed to add spf record, %s\n", err)
	}
}

func main() {
	var filename string
	var h bool
	flag.StringVar(&filename, "c", "./config.json", "Set config file")
	flag.BoolVar(&h, "h", false, "Show help")
	flag.Parse()

	if h {
		flag.Usage()
		os.Exit(0)
	}

	conf, err := config.ReadConf(filename)
	if err != nil {
		log.Panicf("failed to read config file : %s, error: %s\n", filename, err)
	}

	if conf.Log.File != "" {
		file, err := os.OpenFile(conf.Log.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(file)
		defer file.Close()
	}
	if conf.Log.Systemd {
		log.SetFlags(log.Llongfile)
	} else {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Llongfile)
	}

	var c *tpapi.TPSession
	if conf.Router.Stok != "" {
		c = tpapi.TPSessionStok(conf.Router.Url, conf.Router.Stok)
	} else {
		c, err = tpapi.TPSessionPasswd(conf.Router.Url, conf.Router.Passwd)
		if err != nil {
			log.Panicf("Failed to connect to router:%s\n", err)
		}
	}
	c.SetGenerateIPv6(conf.Domain.GenIPv6...)

	zones := make([]*dynv6.Zone, len(conf.Dynv6))
	for i, z := range conf.Dynv6 {
		d, err := dynv6.New(z.Token, z.Zone)
		if err != nil {
			log.Panicf("failed to connect to dynv6 on %s: %s\n", z.Zone, err)
		} else {
			zones[i] = d
		}
	}

	dp := parser.Parser(conf, c)
	dp.SetOnReconnect(func(ipv4 string, ipv6prefix string) {
		log.Printf("reconnected with ipv4: %s, ipv6prefix: %s\n", ipv4, ipv6prefix)
		for i, zone := range zones {
			if zone == nil {
				continue
			}
			ipv6 := strings.Split(ipv6prefix, "/")[0]
			if ipv6 == "::" {
				ipv6 = ""
			}
			_, err := zone.Update(ipv4, ipv6)
			if err != nil {
				log.Printf("failed to update dynv6 zone, %s", err)
			}
			log.Printf("updated ipv4 and ipv6prefix for zone %s", zone.Name)
			if conf.Dynv6[i].SPF.Enabled {
				updateSPF(conf.Dynv6[i].SPF.Name, ipv4, ipv6prefix, zone)
				log.Printf("updated SPF for zone %s", zone.Name)
			}
		}

		for _, dev := range dp.ReadCache() {
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
