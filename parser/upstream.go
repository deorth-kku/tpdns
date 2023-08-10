package parser

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

func resolve(domain string, dnsType uint16, server string) (answer []dns.RR) {
	m := dns.Msg{}
	m.SetQuestion(domain, dnsType)
	r, err := dns.Exchange(&m, server)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Print(r.Extra[0].String())
	return r.Answer
}
