package config

type Dynv6Config struct {
	Token string    `json:"token"`
	Zone  string    `json:"zone"`
	SPF   SPFConfig `json:"spf"`
}

type SPFConfig struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
}
