package tpapi

import (
	"fmt"
	"strconv"
	"strings"
)

const r_ = "redirect_"

func (s *TPSession) AddFwRule(timeout int, port uint16, ipv4 string, ipv6, proto string) (err error) {
	rules, err := s.Getfwrules(timeout)
	if err != nil {
		return
	}
	var num int
	for n := range rules {
		if strings.HasPrefix(n, r_) {
			i, err := strconv.Atoi(strings.Split(n, "_")[1])
			if err != nil {
				return err
			}
			if i > num {
				num = i
			}
		}
	}
	name := fmt.Sprintf("%s%d", r_, num+1)
	data := fmt.Sprintf(`{"firewall":{"table":"redirect","name":"%s","para":{"proto":"%s","src_dport_start":"%d","src_dport_end":"%d","dest_port":"%d","wan_port":0,"dest_ip":"%s","dest_ip6":"%s"}},"method":"add"}`, name, proto, port, port, port, ipv4, ipv6)
	_, err = s.ApiPost(timeout, data)
	return
}

func (s *TPSession) DelFwRule(timeout int, names ...string) (err error) {
	n := strings.Join(names, `","`)
	data := fmt.Sprintf(`{"firewall": {"name": ["%s"]}, "method": "delete"}`, n)
	_, err = s.apiPost(timeout, data)
	return
}
