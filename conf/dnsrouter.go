/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const DNSRouterConfigSuffix = ".dnsrouter.json"
const DomainListFile = "wg_domain_list.txt"

type DNSRouterConfig struct {
	Enabled       bool   `json:"enabled"`
	ListenAddress string `json:"listen_address"`
	DomainListURL string `json:"domain_list_url"`
}

func DefaultDNSRouterConfig() *DNSRouterConfig {
	return &DNSRouterConfig{
		Enabled:       false,
		ListenAddress: "127.0.0.1:53",
		DomainListURL: "",
	}
}

func LoadDNSRouterConfig(tunnelName string) (*DNSRouterConfig, error) {
	if !TunnelNameIsValid(tunnelName) {
		return nil, os.ErrNotExist
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(configFileDir, tunnelName+DNSRouterConfigSuffix)
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg DNSRouterConfig
	err = json.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *DNSRouterConfig) Save(tunnelName string) error {
	if !TunnelNameIsValid(tunnelName) {
		return os.ErrInvalid
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(configFileDir, tunnelName+DNSRouterConfigSuffix)
	bytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, bytes, 0o600)
}

func DeleteDNSRouterConfig(tunnelName string) error {
	if !TunnelNameIsValid(tunnelName) {
		return os.ErrInvalid
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(configFileDir, tunnelName+DNSRouterConfigSuffix)
	return os.Remove(path)
}

// LoadDomainRules parses a dnsmasq-style domain list file.
// Format: server=/domain/ (lines starting with #! are comments).
func LoadDomainRules(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#!") {
			continue
		}
		domain := strings.TrimPrefix(line, "server=/")
		domain = strings.TrimSuffix(domain, "/")
		if domain != "" {
			rules[domain] = struct{}{}
		}
	}
	return rules, nil
}

// MatchDomain performs suffix matching against the domain rule set.
// e.g. "www.google.com" matches rule "google.com".
func MatchDomain(domain string, rules map[string]struct{}) bool {
	parts := strings.Split(domain, ".")
	for i := range parts {
		candidate := strings.Join(parts[i:], ".")
		if _, ok := rules[candidate]; ok {
			return true
		}
	}
	return false
}

// DomainListPath returns the full path to the domain list file.
func DomainListPath() (string, error) {
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(configFileDir, DomainListFile), nil
}

// GenerateDomainListURL generates a remote URL from the config or falls back
// to a default.
func (cfg *DNSRouterConfig) DomainListSourceURL() string {
	if cfg.DomainListURL != "" {
		return cfg.DomainListURL
	}
	return ""
}
