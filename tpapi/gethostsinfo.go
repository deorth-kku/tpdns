package tpapi

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/parnurzeal/gorequest"
)

type hosts_info struct {
	HostsInfo  host_info `json:"hosts_info"`
	Error_code int       `json:"error_code"`
}

type host_info struct {
	HostInfo []deviceline `json:"host_info"`
}
type deviceline map[string]Device

type Device struct {
	MAC          string `json:"mac"`
	ParentMAC    string `json:"parent_mac"`
	IsMesh       string `json:"is_mesh"`
	WiFiMode     string `json:"wifi_mode"`
	Type         string `json:"type"`
	Blocked      string `json:"blocked"`
	IP           string `json:"ip"`
	IPv6         string `json:"ipv6"`
	Hostname     string `json:"hostname"`
	UpSpeed      string `json:"up_speed"`
	DownSpeed    string `json:"down_speed"`
	UpLimit      string `json:"up_limit"`
	DownLimit    string `json:"down_limit"`
	IsCurHost    string `json:"is_cur_host"`
	SSID         string `json:"ssid"`
	ForbidDomain string `json:"forbid_domain"`
	LimitTime    string `json:"limit_time"`
	PlanRule     []any  `json:"plan_rule"`
}

func (s *tpSession) Gethostsinfo(timeout int) (devices []Device, err error) {
	data := `{"hosts_info": {"table": "host_info"}, "method": "get"}`
	_, body, errs := gorequest.New().
		Post(s.apiurl).
		Timeout(time.Duration(timeout) * time.Second).
		Send(data).
		End()
	if errs != nil {
		err = errs[0]
		return
	}
	var h hosts_info
	err = json.Unmarshal([]byte(body), &h)
	if err != nil {
		return
	}
	if h.Error_code != 0 {
		err = fmt.Errorf("get token failed with %d", h.Error_code)
	}
	for _, line := range h.HostsInfo.HostInfo {
		for _, d := range line {
			devices = append(devices, d)
		}
	}
	return
}
