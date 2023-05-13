package config

type LogConfig struct {
	File    string `json:"file"`
	Systemd bool   `json:"systemd"`
}
