package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type ClientConfig struct {
	NicIP    string `json:"nic_ip"`
	ServerIP string `json:"server_ip"`
}

type ServerConfig struct {
	NicIP    string `json:"nic_ip"`
	TunIP    string `json:"tun_ip"`
	ServerID string `json:"server_id"`
	Region   string `json:"region"`
	DbURL    string `json:"db_url"`
}

type Config struct {
	Client ClientConfig `json:"client"`
	Server ServerConfig `json:"server"`
}

func loadConfig(path string) (*Config, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config read failed: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(f, &cfg); err != nil {
		return nil, fmt.Errorf("config parse failed: %w", err)
	}
	return &cfg, nil
}
