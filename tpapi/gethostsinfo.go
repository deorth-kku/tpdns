package tpapi

type hosts_info struct {
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

const Gethostsinfodata = `{"hosts_info": {"table": "host_info"}, "method": "get"}`

func (s *TPSession) Gethostsinfo(timeout int) (devices []Device, err error) {
	h, err := s.ApiPost(timeout, Gethostsinfodata)
	for _, line := range h.HostsInfo.HostInfo {
		for _, d := range line {
			devices = append(devices, d)
		}
	}
	return
}
