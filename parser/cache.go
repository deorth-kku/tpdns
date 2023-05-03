package parser

import (
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/deorth-kku/tpdns/tpapi"
)

func (gdata *dns_parser) flushCache() {
	gdata.needFlush = false
	log.Println("started flushCache")
	ds, err := gdata.tp_conn.ApiPost(1, tpapi.Gethostsinfodata, tpapi.Getwaninfodata)
	if err != nil {
		log.Printf("failed to get hosts info: %s\n", err)
	}

	new_cache := make(map[string]dualstackips, 0)
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
			new_cache[host] = ips

			if _, ok := gdata.dns_cache[host]; !ok {
				//device without a name wont be sent, for now
				gdata.eventDeviceOnline <- info
			}
		}
	}
	gdata.dns_cache = new_cache

	if gdata.pub_ip != ds.Network.WanStatus.IPAddr {
		gdata.pub_ip = ds.Network.WanStatus.IPAddr
		i, err := gdata.tp_conn.Getlanv6info(1)
		if err != nil {
			log.Printf("failed to get lanv6info")
		}
		gdata.eventReconnect <- dualstackips{gdata.pub_ip, i.Prefix}
	}
	gdata.resetTimer <- true
}

func (gdata *dns_parser) ttlCountdown() {
	if gdata.ttl == 0 {
		return
	}
	gdata.countdown = gdata.ttl

	// Loop until interrupted
	for {
		// Check if the timer has reached zero
		if gdata.countdown == 0 {
			gdata.needFlush = true
			gdata.countdown = gdata.ttl
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
			gdata.countdown = gdata.ttl
		default:
			gdata.countdown--
		}
	}
}
