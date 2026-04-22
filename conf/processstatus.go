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

const ProcessStatusSuffix = ".status.json"

type ProcessStatus struct {
	PhantunRunning   bool `json:"phantun_running"`
	DNSCryptRunning  bool `json:"dnscrypt_running"`
	DNSRouterRunning bool `json:"dnsrouter_running"`
}

func LoadProcessStatus(tunnelName string) (*ProcessStatus, error) {
	if !TunnelNameIsValid(tunnelName) {
		return nil, os.ErrNotExist
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(configFileDir, tunnelName+ProcessStatusSuffix)
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var status ProcessStatus
	err = json.Unmarshal(bytes, &status)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func (s *ProcessStatus) Save(tunnelName string) error {
	if !TunnelNameIsValid(tunnelName) {
		return os.ErrInvalid
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(configFileDir, tunnelName+ProcessStatusSuffix)
	bytes, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, bytes, 0o600)
}

func DeleteProcessStatus(tunnelName string) error {
	if !TunnelNameIsValid(tunnelName) {
		return os.ErrInvalid
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(configFileDir, tunnelName+ProcessStatusSuffix)
	return os.Remove(path)
}
