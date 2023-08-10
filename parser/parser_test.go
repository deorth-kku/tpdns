package parser

import (
	"fmt"
	"testing"

	"github.com/deorth-kku/tpdns/config"
	"github.com/deorth-kku/tpdns/tpapi"
	"github.com/miekg/dns"
)

func TestParser(t *testing.T) {
	conf, err := config.ReadConf("../config.json")
	if err != nil {
		t.Error(err)
	}
	c, err := tpapi.TPSessionPasswd(conf.Router.Url, conf.Router.Passwd)
	if err != nil {
		t.Error(err)
	}
	p := Parser(conf, c)

	answers := p.ask([]dns.Question{
		{
			Name:  "abc.wan.",
			Qtype: dns.TypeTXT,
		},
		{
			Name:  "aa.abc.wan.",
			Qtype: dns.TypeA,
		},
		{
			Name:  "mail.deorth.dynv6.net.",
			Qtype: dns.TypeHTTPS,
		},
	})

	for _, answer := range answers {
		fmt.Println(answer.String())
	}
}

func TestUpstream(t *testing.T) {
	a := resolve("v2ex.com.", dns.TypeHTTPS, "127.0.0.1:53")
	if len(a) == 0 {
		t.Error("failed to run upstream dns")
	}
}
