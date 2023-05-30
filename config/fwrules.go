package config

type DevicesFwRules []DeviceFwRules

type DeviceFwRules struct {
	Name  string `json:"name"`
	Mac   string `json:"mac"`
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
}

func (dfr DevicesFwRules) SearchDevice(name string, mac string) (rules []Rule, exist bool) {
	for _, conf_dev := range dfr {
		match_mac := conf_dev.Mac == "" || mac == conf_dev.Mac
		match_name := conf_dev.Name == "" || name == conf_dev.Name
		if match_mac && match_name {
			exist = true
			rules = conf_dev.Rules
		}
	}
	return
}
