package dynv6

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/parnurzeal/gorequest"
)

type Dynv6Zone struct {
	session *gorequest.SuperAgent
	zoneID  int
}

type ZoneDetails struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	IPv4Address string    `json:"ipv4address"`
	IPv6Prefix  string    `json:"ipv6prefix"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

const dynv6api = "https://dynv6.com/api/v2"

func New(token string, zone_name string) (zone Dynv6Zone, err error) {
	t := fmt.Sprintf("Bearer %s", token)
	zone.session = gorequest.New().Set("Authorization", t)
	zone.session.DoNotClearSuperAgent = true
	url, err := url.JoinPath(dynv6api, "zones/by-name", zone_name)
	if err != nil {
		return
	}
	rsp, body, errs := zone.session.Get(url).End()
	if len(errs) != 0 {
		err = errs[0]
		return
	}
	if rsp.StatusCode != 200 {
		err = fmt.Errorf("api return with error: %s", http.StatusText(rsp.StatusCode))
		return
	}

	var zd ZoneDetails
	err = json.Unmarshal([]byte(body), &zd)
	if err != nil {
		return
	}
	zone.zoneID = zd.ID

	return
}
