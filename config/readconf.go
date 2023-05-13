package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type tpdnsConfig struct {
	Router  router          `json:"router"`
	Domain  domain          `json:"domain"`
	Server  server          `json:"server"`
	Dynv6   Dynv6Config     `json:"dynv6"`
	Fwrules []DeviceFwRules `json:"fwrules"`
	Log     LogConfig       `json:"log"`
}

type router struct {
	Url      string `json:"url"`
	Passwd   string `json:"passwd"`
	StokFile string `json:"stok_file"`
	Stok     string `json:"-"`
}

type domain struct {
	PubZone  string   `json:"public_zone_name"`
	PrivZone string   `json:"private_zone_name"`
	GenIPv6  []string `json:"generate_ipv6"`
	TTL      uint     `json:"ttl"`
}

type server struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

func ReadConf(filename string) (c tpdnsConfig, err error) {
	c = tpdnsConfig{
		Domain: domain{TTL: 60},
		Server: server{Port: 53},
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &c)
	if err != nil {
		return
	}
	if c.Router.StokFile != "" {
		data, err = os.ReadFile(c.Router.StokFile)
		if err != nil {
			err = fmt.Errorf("failed to read stok file:%s, error:%s", c.Router.StokFile, err)
			return
		}
		c.Router.Stok = string(data)
	}
	return
}
