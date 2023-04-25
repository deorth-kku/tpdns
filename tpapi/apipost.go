package tpapi

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/parnurzeal/gorequest"
)

type TPResponse struct {
	Network    Network    `json:"network"`
	HostsInfo  hosts_info `json:"hosts_info"`
	Error_code int        `json:"error_code"`
}

func (s *TPSession) ApiPost(timeout int, data ...any) (rsp TPResponse, err error) {
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
	if err != nil {
		return
	}
	if rsp.Error_code != 0 {
		err = fmt.Errorf("get token failed with %d", rsp.Error_code)
	}
	return
}
