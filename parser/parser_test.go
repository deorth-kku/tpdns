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
	q.SetQuestion("abc.wan.", dns.TypeTXT)
	q.Question = append(q.Question, dns.Question{
		Name:  "aa.abc.wan.",
		Qtype: dns.TypeA,
	})
	q.Question = append(q.Question, dns.Question{
		Name:  "mail.deorth.dynv6.net.",
		Qtype: dns.TypeHTTPS,
	})
	p.parseQuery(q)
	for _, answer := range q.Answer {
		fmt.Println(answer.String())
	}
}
