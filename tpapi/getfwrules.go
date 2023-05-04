package tpapi

import "strconv"

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

func (s *TPSession) Getfwrules(timeout int) (rules FwRuleLine, err error) {
	rules = make(FwRuleLine)
	h, err := s.ApiPost(timeout, Getfwrulesdata)
	for _, line := range h.Firewall.Redirect {
		for n, r := range line {
			rules[n] = r
		}
	}
	return
}

func (frl FwRuleLine) Search(proto string, port uint16) (name string, rule FwRule, ok bool) {
	for n, r := range frl {
		if r.DestPort == strconv.Itoa(int(port)) && r.Proto == proto {
			return n, r, true
		}
	}
	return
}
