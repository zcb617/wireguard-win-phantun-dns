/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	Mode          string `json:"mode"`
	TTLMinutes    int    `json:"ttl_minutes"`
}

const (
	DNSRouterModeAllowedIPs = "allowedips"
	DNSRouterModeRouteTable = "routetable"
)

func DefaultDNSRouterConfig() *DNSRouterConfig {
	return &DNSRouterConfig{
		Enabled:       false,
		ListenAddress: "127.0.0.1:53",
		DomainListURL: "https://raw.githubusercontent.com/zcb617/wireguard-win-phantun-dns/refs/heads/master/wg_domain_list.txt",
		Mode:          DNSRouterModeAllowedIPs,
		TTLMinutes:    10,
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

// DownloadDomainListResult describes the outcome of a download attempt.
type DownloadDomainListResult struct {
	Success bool
	Message string
}

// DownloadDomainListIfNeeded downloads the domain list from the configured URL
// if the local file does not exist. It returns a descriptive result so the UI
// can show the user what happened. This is called from the manager service
// which runs with SYSTEM privileges and can write to the configuration directory.
func (cfg *DNSRouterConfig) DownloadDomainListIfNeeded() DownloadDomainListResult {
	if cfg.DomainListURL == "" {
		return DownloadDomainListResult{Success: true, Message: ""}
	}

	listPath, err := DomainListPath()
	if err != nil {
		return DownloadDomainListResult{Success: false, Message: fmt.Sprintf("Failed to get domain list path: %v", err)}
	}

	_, statErr := os.Stat(listPath)
	if statErr == nil {
		return DownloadDomainListResult{Success: true, Message: ""}
	}
	if !os.IsNotExist(statErr) {
		return DownloadDomainListResult{Success: false, Message: fmt.Sprintf("Failed to check domain list file: %v", statErr)}
	}

	resp, err := http.Get(cfg.DomainListURL)
	if err != nil {
		return DownloadDomainListResult{Success: false, Message: fmt.Sprintf("Failed to download: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return DownloadDomainListResult{Success: false, Message: fmt.Sprintf("Server returned HTTP %d", resp.StatusCode)}
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(listPath), 0o700); err != nil {
		return DownloadDomainListResult{Success: false, Message: fmt.Sprintf("Failed to create directory: %v", err)}
	}

	file, err := os.Create(listPath)
	if err != nil {
		return DownloadDomainListResult{Success: false, Message: fmt.Sprintf("Failed to create file: %v", err)}
	}
	defer file.Close()

	n, err := io.Copy(file, resp.Body)
	if err != nil {
		return DownloadDomainListResult{Success: false, Message: fmt.Sprintf("Failed to write file: %v", err)}
	}

	return DownloadDomainListResult{Success: true, Message: fmt.Sprintf("Domain list downloaded (%d bytes) to %s", n, listPath)}
}
