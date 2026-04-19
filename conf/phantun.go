/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const PhantunConfigSuffix = ".phantun.json"

type PhantunConfig struct {
	Enabled bool   `json:"enabled"`
	Remote  string `json:"remote"`
	Local   string `json:"local"`
}

func DefaultPhantunConfig() *PhantunConfig {
	return &PhantunConfig{
		Enabled: false,
		Remote:  "",
		Local:   "127.0.0.1:8080",
	}
}

func LoadPhantunConfig(tunnelName string) (*PhantunConfig, error) {
	if !TunnelNameIsValid(tunnelName) {
		return nil, os.ErrNotExist
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(configFileDir, tunnelName+PhantunConfigSuffix)
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg PhantunConfig
	err = json.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *PhantunConfig) Save(tunnelName string) error {
	if !TunnelNameIsValid(tunnelName) {
		return os.ErrInvalid
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(configFileDir, tunnelName+PhantunConfigSuffix)
	bytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, bytes, 0o600)
}

func DeletePhantunConfig(tunnelName string) error {
	if !TunnelNameIsValid(tunnelName) {
		return os.ErrInvalid
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(configFileDir, tunnelName+PhantunConfigSuffix)
	return os.Remove(path)
}
