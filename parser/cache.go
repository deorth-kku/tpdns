package parser

import (
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/deorth-kku/tpdns/tpapi"
)

func (gdata *dns_parser) flushCache() {
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

func (gdata *dns_parser) clearCache() {
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
