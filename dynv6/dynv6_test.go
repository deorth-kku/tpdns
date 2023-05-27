package dynv6

import (
	"testing"

	"github.com/deorth-kku/tpdns/config"
)

func TestUpdateZone(t *testing.T) {
	c, _ := config.ReadConf("../config.json")
	z, err := New(c.Dynv6[0].Token, "deorth-moonlight.dynv6.net")
	if err != nil {
		t.Error(err)
	}
	_, err = z.Update("192.168.101.1", "")
	if err != nil {
		t.Error(err)
	}
}

func TestGetRecords(t *testing.T) {
	c, _ := config.ReadConf("../config.json")
	z, err := New(c.Dynv6[0].Token, "deorth-moonlight.dynv6.net")
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

func TestAddUpdateDelRecord(t *testing.T) {
	c, _ := config.ReadConf("../config.json")
	z, err := New(c.Dynv6[0].Token, "deorth-moonlight.dynv6.net")
	if err != nil {
		t.Error(err)
	}
	r, err := z.AddRecord(RecordInfo{Name: "test", Data: "this is a test", Type: "TXT"})
	if err != nil {
		t.Error(err)
	}

	_, err = r.Update(RecordInfo{Name: "test", Data: "this is a test 2", Type: "TXT"})
	if err != nil {
		t.Error(err)
	}
	if r.Data != "this is a test 2" {
		t.Error("failed to update struct")
	}

	err = r.Delete()
	if err != nil {
		t.Error(err)
	}
}
