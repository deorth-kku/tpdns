package config

type DeviceFwRules struct {
	Name  string `json:"name"`
	Mac   string `json:"mac"`
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
}
