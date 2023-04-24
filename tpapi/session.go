package tpapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/parnurzeal/gorequest"
)

type tpSession struct {
	site   string
	passwd string
	stok   string
	apiurl string
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

func TPSessionStok(site string, stok string) (session tpSession) {
	session = tpSession{site: site, stok: stok}
	session.flushapi()
	return
}

func TPSessionPasswd(site string, passwd string) (session tpSession, err error) {
	session = tpSession{site: site, passwd: passwdEncryption(passwd)}
	err = session.flushstok()
	return
}

func (s *tpSession) flushstok() error {
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
		return fmt.Errorf("get token failed with %d", rsp.Error_code)
	}
	s.stok = rsp.Stok
	s.flushapi()
	return nil
}

func (s *tpSession) flushapi() {
	s.apiurl, _ = url.JoinPath(s.site, fmt.Sprintf("stok=%s/ds", s.stok))
}
