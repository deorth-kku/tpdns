package tpapi

import (
	"testing"

	"github.com/deorth-kku/tpdns/config"
)

func getconn(t *testing.T) *TPSession {
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
	c.SetGenerateIPv6("next-terminal")
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
		t.Error("Getfwrules returned empty list")
	}
}

func TestSetfwrules(t *testing.T) {
	c := getconn(t)
	for i := uint16(10000); i < 10002; i++ {
		err := c.AddFwRule(1, i, "192.168.101.254", "", "all")
		if err != nil {
			t.Error(err)
		}
	}
	rs, err := c.Getfwrules(5)
	if err != nil {
		t.Error(err)
	}
	var names []string
	for n, r := range rs {
		if r.DestPort == "10000" || r.DestPort == "10001" {
			names = append(names, n)
		}
	}
	err = c.DelFwRule(1, names...)
	if err != nil {
		t.Error(err)
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

func TestGenv6(t *testing.T) {
	v6, err := Gen_v6("240e:3b7:694:54a0::", "3c:06:a7:43:d2:76")
	if err != nil {
		t.Error(err)
		return
	}
	if v6 != "240e:3b7:694:54a0:3e06:a7ff:fe43:d276" {
		t.Errorf("generated ipv6 did not match %s", v6)
	}
}

func TestGetwanLanv6(t *testing.T) {
	c := getconn(t)
	i, err := c.ApiPost(1, Getwanlanv6infodata)
	if err != nil {
		t.Error(err)
		return
	}
	if i.Network.WanStatus.IPAddr == "" {
		t.Error("failed to get ipv4 wan")
	}
	if i.Network.Lanv6Status.Ip6addr == "" {
		t.Error("failed to get ipv6 lan")
	}
}
