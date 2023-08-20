package dynv6

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type UpdatePayload struct {
	IPv4Address string `json:"ipv4address"`
	IPv6Prefix  string `json:"ipv6prefix"`
}

func (z *Zone) Update(ipv4address string, ipv6prefix string) (zd Zone, err error) {
	url, err := url.JoinPath(dynv6api, fmt.Sprintf("zones/%d", z.ID))
	if err != nil {
		return
	}
	resp, body, errs := z.session.Patch(url).
		Send(UpdatePayload{ipv4address, ipv6prefix}).
		EndBytes()
	if len(errs) != 0 {
		err = errs[0]
		return
	}
	switch resp.StatusCode {
	case 200:
		err = json.Unmarshal(body, &zd)
	case 422:
		var e error422
		err = json.Unmarshal(body, &e)
		if err != nil {
			return
		}
		err = fmt.Errorf("%s: %s", e.Name, e.Message)

	default:
		err = fmt.Errorf("api return with error: %s", http.StatusText(resp.StatusCode))

	}
	return
}

func (z *Zone) CheckUpdate(ipv4address string, ipv6prefix string) (zd Zone, err error) {
	if ipv4address == z.IPv4Address && ipv6prefix == z.IPv6Prefix {
		return *z, nil
	}
	return z.Update(ipv4address, ipv6prefix)
}
