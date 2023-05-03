package tpapi

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/parnurzeal/gorequest"
)

type Network struct {
	WanStatus   WanInfo   `json:"wan_status"`
	WanStatus2  WanInfo   `json:"wan_status_2"`
	Lanv6Status Lanv6Info `json:"lanv6_status"`
}

type TPResponse struct {
	Network    Network    `json:"network"`
	HostsInfo  hosts_info `json:"hosts_info"`
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
		err = fmt.Errorf("get token failed with %s", Tp_errors[rsp.Error_code])
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
	return
}
