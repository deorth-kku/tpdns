package parser

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/deorth-kku/tpdns/tpapi"
)

func (dp *dns_parser) ReadCache() map[string]tpapi.Device {
	return dp.dns_cache
}

func (gdata *dns_parser) flushCache(event_enabled bool) {
	gdata.cache_lock.Lock()
	gdata.needFlush = false
	log.Println("started flushCache")
	ds, err := gdata.TpSession.ApiPost(1, tpapi.Gethostsinfodata, tpapi.Getwanlanv6infodata)
	if err != nil {
		log.Printf("failed to flush cache: %s\n", err)
	} else {
		new_cache := make(map[string]tpapi.Device, 0)
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
				new_cache[host] = info

				if _, ok := gdata.dns_cache[host]; !ok && event_enabled {
					//device without a name wont be sent, for now
					gdata.eventDeviceOnline <- info
				}
			}
		}

		gdata.dns_cache = new_cache

		ipv6prefix := fmt.Sprintf("%s/%s", ds.Network.Lanv6Status.Prefix, ds.Network.Lanv6Status.Prefixlen)
		if (ds.Network.WanStatus.IPAddr != "" && gdata.pub_ip.IPv4 != ds.Network.WanStatus.IPAddr) || ipv6prefix != gdata.pub_ip.IPv6 {
			gdata.pub_ip = dualstackips{ds.Network.WanStatus.IPAddr, ipv6prefix}
			if event_enabled {
				gdata.eventReconnect <- gdata.pub_ip
			}

		}
		gdata.resetTimer <- true
		log.Println("finished flushCache")
	}

	gdata.cache_lock.Unlock()

}

func (gdata *dns_parser) ttlCountdown() {
	if gdata.Conf.Domain.TTL == 0 {
		return
	}
	gdata.countdown = gdata.Conf.Domain.TTL

	// Loop until interrupted
	for {
		// Check if the timer has reached zero
		if gdata.countdown == 0 {
			gdata.needFlush = true
			gdata.countdown = gdata.Conf.Domain.TTL
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
			gdata.countdown = gdata.Conf.Domain.TTL
		default:
			gdata.countdown--
		}
	}
}
