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
	RecordInfo
	ExpandedData string `json:"expandedData"`
	ID           uint   `json:"id"`
	ZoneID       uint   `json:"zoneID"`
}

type RecordInfo struct {
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
	resp, body, errs := z.session.Get(url).EndBytes()
	if len(errs) != 0 {
		err = errs[0]
		return
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal(body, &records)
		for i := range records {
			records[i].session = z.session
		}
	} else {
		err = fmt.Errorf("api return with error: %s", http.StatusText(resp.StatusCode))
	}

	return
}

func (z *Zone) AddRecord(info RecordInfo) (record Record, err error) {
	url, err := url.JoinPath(dynv6api, fmt.Sprintf("zones/%d/records", z.ID))
	if err != nil {
		return
	}
	resp, body, errs := z.session.Post(url).
		Send(info).
		EndBytes()
	if len(errs) != 0 {
		err = errs[0]
		return
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal(body, &record)
		record.session = z.session
	} else {
		err = fmt.Errorf("api return with error: %s", http.StatusText(resp.StatusCode))
	}
	return
}

func (r *Record) GetRecord(info RecordInfo) (record Record, err error) {
	url, err := url.JoinPath(dynv6api, fmt.Sprintf("zones/%d/records/%d", r.ZoneID, r.ID))
	if err != nil {
		return
	}
	resp, body, errs := r.session.Get(url).EndBytes()
	if len(errs) != 0 {
		err = errs[0]
		return
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal(body, r)
		record = *r
	} else {
		err = fmt.Errorf("api return with error: %s", http.StatusText(resp.StatusCode))
	}
	return
}

func (r *Record) Update(info RecordInfo) (record Record, err error) {
	url, err := url.JoinPath(dynv6api, fmt.Sprintf("zones/%d/records/%d", r.ZoneID, r.ID))
	if err != nil {
		return
	}
	resp, body, errs := r.session.Patch(url).
		Send(info).
		EndBytes()
	if len(errs) != 0 {
		err = errs[0]
		return
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal(body, r)
		record = *r
	} else {
		err = fmt.Errorf("api return with error: %s", http.StatusText(resp.StatusCode))
	}
	return
}

func (r *Record) Delete() (err error) {
	url, err := url.JoinPath(dynv6api, fmt.Sprintf("zones/%d/records/%d", r.ZoneID, r.ID))
	if err != nil {
		return
	}
	resp, _, errs := r.session.Delete(url).EndBytes()
	if len(errs) != 0 {
		err = errs[0]
		return
	}
	if resp.StatusCode != 204 {
		err = fmt.Errorf("api return with error: %s", http.StatusText(resp.StatusCode))
	}
	return
}
