package dynv6

import (
	"testing"

	"github.com/deorth-kku/tpdns/config"
)

func TestUpdateZone(t *testing.T) {
	c, _ := config.ReadConf("../config.json")
	z, err := New(c.Dynv6.Token, "deorth-moonlight.dynv6.net")
	if err != nil {
		t.Error(err)
	}
	_, err = z.Update("192.168.101.1", "fe80::1")
	if err != nil {
		t.Error(err)
	}
}

func TestGetRecords(t *testing.T) {
	c, _ := config.ReadConf("../config.json")
	z, err := New(c.Dynv6.Token, "deorth-moonlight.dynv6.net")
	if err != nil {
		t.Error(err)
	}
	rs, err := z.GetRecords()
	if err != nil {
		t.Error(err)
	}
	if len(rs) == 0 {
		t.Error("No records found")
	}
}
