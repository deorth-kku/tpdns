package tpapi


type WanInfo struct {
	IPAddr     string `json:"ipaddr"`
	Netmask    string `json:"netmask"`
	Gateway    string `json:"gateway"`
	PriDNS     string `json:"pri_dns"`
	SndDNS     string `json:"snd_dns"`
	LinkStatus int    `json:"link_status"`
	ErrorCode  int    `json:"error_code"`
	Proto      string `json:"proto"`
	UpTime     int    `json:"up_time"`
	UpSpeed    int    `json:"up_speed"`
	DownSpeed  int    `json:"down_speed"`
	PhyStatus  int    `json:"phy_status"`
}

const Getwaninfodata = `{"network": {"name": ["wan_status"]},"method": "get"}`

func (s *TPSession) Getwaninfo(timeout int) (info WanInfo, err error) {
	rsp, err := s.ApiPost(timeout, Getwaninfodata)
	info = rsp.Network.WanStatus
	return
}
