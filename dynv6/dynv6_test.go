package dynv6

import "testing"

func TestUpdateZone(t *testing.T) {
	z, err := New("dz2rLVM2gL3mpK8Hbuz43wdgKajcJs", "deorth-moonlight.dynv6.net")
	if err != nil {
		t.Error(err)
	}
	_, err = z.Update("192.168.101.256", "fe80::")
	if err != nil {
		t.Error(err)
	}
}
