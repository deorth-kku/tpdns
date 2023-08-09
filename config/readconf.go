package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
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
	Zones          []Zone   `json:"zones"`
	GenIPv6        []string `json:"generate_ipv6"`
	TTL            uint     `json:"ttl"`
	UpstreamServer string   `json:"upstream_server"`
}

type Zone struct {
	Name          string  `json:"name"`
	DefaultDevice string  `json:"default_device"`
	Records       Records `json:"records"`
	GlobalIPv4    bool    `json:"global_ipv4"`
	GlobalIPv6    bool    `json:"global_ipv6"`
}

type record struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Value    string         `json:"value"`
	Template TemplateRecord `json:"template"`
	re       *regexp.Regexp `json:"-"`
}

type TemplateRecord struct {
	DeviceName string   `json:"device"`
	Args       []string `json:"args"`
}

func (tt TemplateRecord) IsEmpty() bool {
	return tt.DeviceName == "" && len(tt.Args) == 0
}

type Records []record

func (rs Records) Match(device_name string, rr_type string) (rec record, ok bool) {
	for _, r := range rs {
		var domain_match bool
		if r.re == nil {
			domain_match = device_name == r.Name
		} else {
			domain_match = r.re.MatchString(device_name)
		}
		if domain_match && rr_type == r.Type {
			return r, true
		}
	}
	return rec, false
}

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
	for _, zone := range c.Domain.Zones {
		for j, record := range zone.Records {
			//update regex for matching
			if !strings.HasSuffix(record.Name, ".") {
				zone.Records[j].re = regexp.MustCompile("^" + record.Name + "$")
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
	if c.Domain.UpstreamServer == "" {
		var f *os.File
		f, err = os.Open("/etc/resolv.conf")
		if err != nil {
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "nameserver") {
				line = line[10:]
				c.Domain.UpstreamServer = strings.TrimSpace(line) + ":53"
				break
			}
		}
	} else {
		validate := validator.New()
		err = validate.Var(c.Domain.UpstreamServer, "hostname_port")
		if err != nil {
			return
		}
	}
	return
}
