package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/exp/slices"
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
	Zones   []Zone   `json:"zones"`
	GenIPv6 []string `json:"generate_ipv6"`
	TTL     uint     `json:"ttl"`
}

type Zone struct {
	Name          string            `json:"name"`
	DefaultDevice string            `json:"default_device"`
	Records       Records           `json:"records"`
	GlobalIPv4    bool              `json:"global_ipv4"`
	GlobalIPv6    bool              `json:"global_ipv6"`
	CNAMEs        map[string]string `json:"-"`
}

type record struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Value    string         `json:"value"`
	Template TemplateRecord `json:"template"`
}

type TemplateRecord struct {
	DeviceName string   `json:"device"`
	Args       []string `json:"args"`
}

func (tt TemplateRecord) IsEmpty() bool {
	return tt.DeviceName == "" && len(tt.Args) == 0
}

type Records []record

type server struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

var allowed_args = []string{
	"MAC",
	"ParentMAC",
	"IsMesh",
	"WiFiMode",
	"Type",
	"Blocked",
	"IP",
	"IPv6",
	"Hostname",
	"UpSpeed",
	"DownSpeed",
	"UpLimit",
	"DownLimit",
	"IsCurHost",
	"SSID",
	"ForbidDomain",
	"LimitTime",
}

func check_args(args []string) error {
	for _, arg := range args {
		if !slices.Contains(allowed_args, arg) {
			return fmt.Errorf("%s is not an allowed args", arg)
		}
	}
	return nil
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
	for i, zone := range c.Domain.Zones {
		c.Domain.Zones[i].CNAMEs = make(map[string]string)
		for _, record := range zone.Records {
			//update CNAME to CNAMEs table
			if record.Type == "CNAME" {
				c.Domain.Zones[i].CNAMEs[record.Name] = record.Value
			}
			//check if record template is vaild
			if !record.Template.IsEmpty() {
				err = check_args(record.Template.Args)
				if err != nil {
					return
				}
				if strings.Count(record.Value, "%s") != len(record.Template.Args) {
					err = fmt.Errorf("record %s type %s template does not match args", record.Name, record.Type)
					return
				}
			}
		}
	}
	return
}
