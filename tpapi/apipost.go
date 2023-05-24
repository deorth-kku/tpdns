package tpapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/parnurzeal/gorequest"
	"golang.org/x/exp/slices"
)

type Network struct {
	WanStatus   WanInfo   `json:"wan_status"`
	WanStatus2  WanInfo   `json:"wan_status_2"`
	Lanv6Status Lanv6Info `json:"lanv6_status"`
}

type TPResponse struct {
	Network    Network    `json:"network"`
	HostsInfo  hosts_info `json:"hosts_info"`
	Firewall   FwRules    `json:"firewall"`
	Error_code int        `json:"error_code"`
}

func (s *TPSession) ApiPost(timeout int, data ...any) (rsp TPResponse, err error) {
	rsp, err = s.apiPost(timeout, data...)
	if err != nil {
		return
	} else if rsp.Error_code == EUNAUTH {
		err = s.flushstok()
		if err != nil {
			return
		}
		rsp, err = s.apiPost(timeout, data...)
	}

	if rsp.Error_code != ENONE {
		err = fmt.Errorf("api post failed with %s", Tp_errors[rsp.Error_code])
	}
	return
}

func (s *TPSession) apiPost(timeout int, data ...any) (rsp TPResponse, err error) {
	r := gorequest.New().
		Post(s.apiurl).
		Timeout(time.Duration(timeout) * time.Second)
	for _, d := range data {
		r.Send(d)
	}
	_, body, errs := r.End()
	if errs != nil {
		err = errs[0]
		return
	}
	err = json.Unmarshal([]byte(body), &rsp)
	if len(s.generate_ipv6) != 0 && len(rsp.HostsInfo.HostInfo) != 0 {
		var prefix string
		if rsp.Network.Lanv6Status.Prefix != "" {
			prefix = rsp.Network.Lanv6Status.Prefix
		} else {
			t, _ := s.Getlanv6info(timeout)
			prefix = t.Prefix
		}
		for i, line := range rsp.HostsInfo.HostInfo {
			for j, host := range line {
				if host.IPv6 != "::" {
					continue
				}
				devname, err := url.QueryUnescape(host.Hostname)
				if err != nil {
					devname = host.Hostname
				}
				if !slices.Contains(s.generate_ipv6, devname) {
					continue
				}
				gened_v6, err := Gen_v6(prefix, host.MAC)
				if err != nil {
					continue
				}
				rsp.update_v6(i, j, gened_v6)
			}
		}
	}
	return
}

func (r *TPResponse) update_v6(i int, j string, ipv6 string) {
	m := r.HostsInfo.HostInfo[i][j]
	m.IPv6 = ipv6
	r.HostsInfo.HostInfo[i][j] = m
}

func Gen_v6(prefix string, macAddr string) (v6 string, err error) {
	macAddr = strings.Replace(macAddr, "-", ":", 5)
	// Parse the MAC address string
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return "", fmt.Errorf("failed to parse MAC address: %v", err)
	}
	mac[0] ^= 0x02

	// Parse the IPv6 prefix string

	ip := net.ParseIP(prefix)
	if ip == nil {
		return "", fmt.Errorf("failed to parse prefix: %v", err)
	}
	// Construct the IPv6 SLAAC address
	ip[8] = mac[0]
	ip[9] = mac[1]
	ip[10] = mac[2]
	ip[11] = 0xff
	ip[12] = 0xfe
	ip[13] = mac[3]
	ip[14] = mac[4]
	ip[15] = mac[5]

	return ip.String(), nil
}
