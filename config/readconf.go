package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type TpdnsConfig struct {
	Router  router         `json:"router"`
	Domain  domain         `json:"domain"`
	Server  server         `json:"server"`
	Dynv6   []Dynv6Config  `json:"dynv6"`
	Fwrules DevicesFwRules `json:"fwrules"`
	Log     LogConfig      `json:"log"`
}

type router struct {
	Url      string `json:"url"`
	Passwd   string `json:"passwd"`
	StokFile string `json:"stok_file"`
	Stok     string `json:"-"`
}

type domain struct {
	PubZone  zone     `json:"public_zone"`
	PrivZone zone     `json:"private_zone"`
	GenIPv6  []string `json:"generate_ipv6"`
	TTL      uint     `json:"ttl"`
}

type zone struct {
	Name       string  `json:"name"`
	Records    Records `json:"records"`
	GlobalIPv6 bool    `json:"pglobal_ipv6"`
}

type record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Records []record

type server struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

func ReadConf(filename string) (c *TpdnsConfig, err error) {
	c = &TpdnsConfig{
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
