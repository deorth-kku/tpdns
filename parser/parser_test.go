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

	q := new(dns.Msg)
	q.Question = append(q.Question, dns.Question{
		Name:  "pve.lan.",
		Qtype: dns.TypeA,
	})
	q.Question = append(q.Question, dns.Question{
		Name:  "pve.wan.",
		Qtype: dns.TypeTXT,
	})
	q.Question = append(q.Question, dns.Question{
		Name:  "pve.wan.",
		Qtype: dns.TypeHTTPS,
	})
	p.parseQuery(q)
	for _, answer := range q.Answer {
		fmt.Println(answer.String())
	}
}
