package dynv6

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type error422 struct {
	errorinfo
	Fields []errorinfo `json:"fields"`
}

type errorinfo struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

type UpdatePayload struct {
	IPv4Address string `json:"ipv4address"`
	IPv6Prefix  string `json:"ipv6prefix"`
}

func (z *Dynv6Zone) Update(ipv4address string, ipv6prefix string) (zd ZoneDetails, err error) {
	url, err := url.JoinPath(dynv6api, fmt.Sprintf("zones/%d", z.zoneID))
	if err != nil {
		return
	}
	resp, body, errs := z.session.Patch(url).
		Send(UpdatePayload{ipv4address, ipv6prefix}).
		End()
	if len(errs) != 0 {
		err = errs[0]
		return
	}
	switch resp.StatusCode {
	case 200:
		err = json.Unmarshal([]byte(body), &zd)
	case 422:
		var e error422
		err = json.Unmarshal([]byte(body), &e)
		if err != nil {
			return
		}
		err = fmt.Errorf("%s: %s", e.Name, e.Message)

	default:
		err = fmt.Errorf("api return with error: %s", http.StatusText(resp.StatusCode))

	}
	return
}
