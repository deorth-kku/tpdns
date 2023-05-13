package dynv6

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/parnurzeal/gorequest"
)

type Record struct {
	session *gorequest.SuperAgent
	ReqRecord
	ExpandedData string `json:"expandedData"`
	ID           uint   `json:"id"`
	ZoneID       uint   `json:"zoneID"`
}

type ReqRecord struct {
	Name     string `json:"name"`
	Priority uint16 `json:"priority"`
	Port     uint16 `json:"port"`
	Weight   uint16 `json:"weight"`
	Flags    uint16 `json:"flags"`
	Tag      string `json:"tag"`
	Data     string `json:"data"`
	Type     string `json:"type"`
}

func (z *Zone) GetRecords() (records []Record, err error) {
	url, err := url.JoinPath(dynv6api, fmt.Sprintf("zones/%d/records", z.ID))
	if err != nil {
		return
	}
	resp, body, errs := z.session.Get(url).End()
	if len(errs) != 0 {
		err = errs[0]
		return
	}
	switch resp.StatusCode {
	case 200:
		err = json.Unmarshal([]byte(body), &records)
	default:
		err = fmt.Errorf("api return with error: %s", http.StatusText(resp.StatusCode))
	}
	for i := range records {
		records[i].session = z.session
	}
	return
}
