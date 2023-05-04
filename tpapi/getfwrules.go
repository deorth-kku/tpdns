package tpapi

type FwRules struct {
	Redirect []FwRuleLine `json:"redirect"`
}

type FwRuleLine map[string]FwRule

type FwRule struct {
	Proto         string `json:"proto"`
	SrcDPortStart string `json:"src_dport_start"`
	SrcDPortEnd   string `json:"src_dport_end"`
	DestPort      string `json:"dest_port"`
	DestIP        string `json:"dest_ip"`
	WANPort       string `json:"wan_port"`
	DestIP6       string `json:"dest_ip6"`
}

const Getfwrulesdata = `{"firewall": {"table": "redirect"}, "method": "get"}`

func (s *TPSession) Getfwrules(timeout int) (rules []FwRule, err error) {
	h, err := s.ApiPost(timeout, Getfwrulesdata)
	for _, line := range h.Firewall.Redirect {
		for _, r := range line {
			rules = append(rules, r)
		}
	}
	return
}
