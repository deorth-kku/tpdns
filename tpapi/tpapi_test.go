package tpapi

import (
	"testing"

	"github.com/deorth-kku/tpdns/config"
)

func getconn(t *testing.T) TPSession {
	conf, err := config.ReadConf("../config.json")
	if err != nil {
		t.Error(err)
	}
	c := TPSessionStok(conf.Router.Url, conf.Router.Stok)
	return c
}

func TestPasswdEncryption(t *testing.T) {
	result := passwdEncryption("123456")
	expected := "0KcgeXhc9TefbwK"
	if result != expected {
		t.Errorf("PasswdEncryption('123456') = %s; expected %s", result, expected)
	}
}

func TestGethostinfo(t *testing.T) {
	c := getconn(t)
	ds, err := c.Gethostsinfo(5)
	if err != nil {
		t.Error(err)
	}
	if len(ds) == 0 {
		t.Error("Gethostsinfo returned empty list")
	}
}

func TestGetfwrules(t *testing.T) {
	c := getconn(t)
	rs, err := c.Getfwrules(5)
	if err != nil {
		t.Error(err)
	}
	if len(rs) == 0 {
		t.Error("Gethostsinfo returned empty list")
	}
}

func TestGetwaninfo(t *testing.T) {
	c := getconn(t)
	d, err := c.Getwaninfo(5)
	if err != nil {
		t.Error(err)
	}
	if d.IPAddr == "" {
		t.Error("Getwaninfo returned empty info")
	}
}

func TestGetboth(t *testing.T) {
	c := getconn(t)
	d, err := c.ApiPost(5, Gethostsinfodata, Getwaninfodata)
	if err != nil {
		t.Error(err)
	}
	if len(d.HostsInfo.HostInfo) == 0 {
		t.Error("Gethostsinfo returned empty list")
	}
	if d.Network.WanStatus.IPAddr == "" {
		t.Error("Getwaninfo returned empty info")
	}

}

func TestAuthRetry(t *testing.T) {
	conf, err := config.ReadConf("../config.json")
	if err != nil {
		t.Error(err)
	}
	c := TPSessionStok(conf.Router.Url, "FakeStokWontWork")
	c.passwd = passwdEncryption(conf.Router.Passwd)
	d, err := c.Getwaninfo(5)
	if err != nil {
		t.Error(err)
	}
	if d.IPAddr == "" {
		t.Error("Getwaninfo returned empty info")
	}

}
