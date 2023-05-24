package tpapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/parnurzeal/gorequest"
)

type TPSession struct {
	site          string
	passwd        string
	stok          string
	apiurl        string
	generate_ipv6 []string
}

type loginRequest struct {
	Method string    `json:"method"`
	Login  loginData `json:"login,omitempty"`
}

type loginData struct {
	Password string `json:"password,omitempty"`
}

type loginRsp struct {
	Error_code int    `json:"error_code"`
	Stok       string `json:"stok"`
}

func TPSessionStok(site string, stok string) (session *TPSession) {
	session = &TPSession{site: site, stok: stok}
	session.flushapi()
	return
}

func TPSessionPasswd(site string, passwd string) (session *TPSession, err error) {
	session = &TPSession{site: site, passwd: passwdEncryption(passwd)}
	err = session.flushstok()
	return
}

func (s *TPSession) flushstok() error {
	data := loginRequest{Method: "do", Login: loginData{Password: s.passwd}}
	_, body, errs := gorequest.New().
		Post(s.site).
		Timeout(5 * time.Second).
		Send(data).
		End()
	if errs != nil {
		return errs[0]
	}
	var rsp loginRsp
	err := json.Unmarshal([]byte(body), &rsp)
	if err != nil {
		return err

	}
	if rsp.Error_code != 0 {
		return fmt.Errorf("get token failed with %s", Tp_errors[rsp.Error_code])
	}
	s.stok = rsp.Stok
	s.flushapi()
	return nil
}

func (s *TPSession) flushapi() {
	s.apiurl, _ = url.JoinPath(s.site, fmt.Sprintf("stok=%s/ds", s.stok))
}

func (s *TPSession) SetGenerateIPv6(names ...string) {
	s.generate_ipv6 = append(s.generate_ipv6, names...)
}
