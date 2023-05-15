package tpapi

type Lanv6Info struct {
	Ip6addr       string `json:"ip6addr"`
	Prefix        string `json:"prefix"`
	Prefixlen     string `json:"prefixlen"`
	Pri_dns       string `json:"pri_dns"`
	Snd_dns       string `json:"snd_dns"`
	Proto         string `json:"proto"`
	Local_ip6addr string `json:"local_ip6addr"`
}

const Getlanv6infodata = `{"network":{"name":"lanv6_status"},"method":"get"}`
const Getwanlanv6infodata = `{"network": {"name": ["wan_status","lanv6_status"]},"method": "get"}`

func (s *TPSession) Getlanv6info(timeout int) (info Lanv6Info, err error) {
	rsp, err := s.ApiPost(timeout, Getlanv6infodata)
	info = rsp.Network.Lanv6Status
	return
}
