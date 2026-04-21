/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type tunnelService struct {
	Path string
}

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	serviceState := svc.StartPending
	changes <- svc.Status{State: serviceState}

	var watcher *interfaceWatcher
	var adapter *driver.Adapter
	var luid winipcfg.LUID
	var config *conf.Config
	var err error
	serviceError := services.ErrorSuccess
	var phantunProcess *os.Process
	var originalEndpoints []conf.Endpoint
	var dnscryptProcess *os.Process
	var originalDNS []netip.Addr
	var dnsRouterInst *dnsRouter
	var ipSyncer *allowedIPsSyncer
	var routeSyncer *routeTableSyncer
	var dnscryptListenAddr string
	var physicalDNSOverrides []winipcfg.PhysicalDNSOverride
	var dnscryptCmd *exec.Cmd
	var originalServers []netip.Addr
	var dnscryptUpstream string

	defer func() {
		if phantunProcess != nil {
			log.Println("Stopping phantun client")
			phantunProcess.Kill()
			phantunProcess.Wait()
		}
		if dnscryptProcess != nil {
			log.Println("Stopping dnscrypt-proxy")
			dnscryptProcess.Kill()
			dnscryptProcess.Wait()
		}
		if dnsRouterInst != nil {
			log.Println("Stopping DNS router")
			dnsRouterInst.Stop()
		}
		if ipSyncer != nil {
			log.Println("Stopping AllowedIPs syncer")
			ipSyncer.Stop()
		}
		if routeSyncer != nil {
			log.Println("Stopping route table syncer")
			routeSyncer.Stop()
		}
		// Restore original DNS if it was modified
		if len(originalDNS) > 0 && config != nil {
			config.Interface.DNS = originalDNS
		}
		// Restore physical adapter DNS if it was overridden
		if len(physicalDNSOverrides) > 0 {
			log.Println("Restoring physical adapter DNS")
			winipcfg.RestorePhysicalDNS(physicalDNSOverrides)
		}
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Println(logErr)
		}
		serviceState = svc.StopPending
		changes <- svc.Status{State: serviceState}

		stopIt := make(chan bool, 1)
		go func() {
			t := time.NewTicker(time.Second * 30)
			for {
				select {
				case <-t.C:
					t.Stop()
					buf := make([]byte, 1024)
					for {
						n := runtime.Stack(buf, true)
						if n < len(buf) {
							buf = buf[:n]
							break
						}
						buf = make([]byte, 2*len(buf))
					}
					lines := bytes.Split(buf, []byte{'\n'})
					log.Println("Failed to shutdown after 30 seconds. Probably dead locked. Printing stack and killing.")
					for _, line := range lines {
						if len(bytes.TrimSpace(line)) > 0 {
							log.Println(string(line))
						}
					}
					os.Exit(777)
					return
				case <-stopIt:
					t.Stop()
					return
				}
			}
		}()

		if logErr == nil && adapter != nil && config != nil {
			logErr = runScriptCommand(config.Interface.PreDown, config.Name)
		}
		if watcher != nil {
			watcher.Destroy()
		}
		if adapter != nil {
			adapter.Close()
		}
		if logErr == nil && adapter != nil && config != nil {
			_ = runScriptCommand(config.Interface.PostDown, config.Name)
		}
		stopIt <- true
		log.Println("Shutting down")
	}()

	var logFile string
	logFile, err = conf.LogFile(true)
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}
	err = ringlogger.InitGlobalLogger(logFile, "TUN")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}

	config, err = conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}
	config.DeduplicateNetworkEntries()

	log.SetPrefix(fmt.Sprintf("[%s] ", config.Name))

	services.PrintStarting()

	if services.StartedAtBoot() {
		if m, err := mgr.Connect(); err == nil {
			if lockStatus, err := m.LockStatus(); err == nil && lockStatus.IsLocked {
				/* If we don't do this, then the driver installation will block forever, because
				 * installing a network adapter starts the driver service too. Apparently at boot time,
				 * Windows 8.1 locks the SCM for each service start, creating a deadlock if we don't
				 * announce that we're running before starting additional services.
				 */
				log.Printf("SCM locked for %v by %s, marking service as started", lockStatus.Age, lockStatus.Owner)
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState}
			}
			m.Disconnect()
		}
	}

	evaluateStaticPitfalls()

	log.Println("Watching network interfaces")
	watcher, err = watchInterface()
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return
	}

	log.Println("Resolving DNS names")
	err = config.ResolveEndpoints()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}

	// Check and start phantun obfuscation if configured
	phantunConfig, phantunErr := conf.LoadPhantunConfig(config.Name)
	if phantunErr == nil && phantunConfig.Enabled && phantunConfig.Remote != "" {
		log.Println("Starting phantun obfuscation")
		exePath, err := os.Executable()
		if err != nil {
			exePath = os.Args[0]
		}
		phantunExe := filepath.Join(filepath.Dir(exePath), "phantun-client.exe")
		if _, statErr := os.Stat(phantunExe); os.IsNotExist(statErr) {
			err = fmt.Errorf("phantun-client.exe not found at %s", phantunExe)
			serviceError = services.ErrorPhantunClient
			return
		}
		phantunArgs := []string{
			"--remote", phantunConfig.Remote,
			"--local", phantunConfig.Local,
			"--ipv4-only",
		}
		// Save original endpoints and replace with phantun local address
		originalEndpoints = make([]conf.Endpoint, len(config.Peers))
		for i := range config.Peers {
			originalEndpoints[i] = config.Peers[i].Endpoint
			config.Peers[i].Endpoint = conf.Endpoint{Host: "127.0.0.1", Port: parsePhantunLocalPort(phantunConfig.Local)}
		}
		cmd := exec.Command(phantunExe, phantunArgs...)
		cmd.Dir = filepath.Dir(phantunExe)
		cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
		if cmdErr := cmd.Start(); cmdErr != nil {
			// Restore original endpoints before returning
			for i := range config.Peers {
				config.Peers[i].Endpoint = originalEndpoints[i]
			}
			err = fmt.Errorf("failed to start phantun-client: %w", cmdErr)
			serviceError = services.ErrorPhantunClient
			return
		}
		phantunProcess = cmd.Process
		log.Println("Phantun client started")
	}

	// Check and start DNSCrypt proxy if configured
	dnsCryptConfig, dnsErr := conf.LoadDNSCryptConfig(config.Name)
	if dnsErr == nil && dnsCryptConfig.Enabled {
		log.Println("Starting DNSCrypt proxy")
		exePath, err := os.Executable()
		if err != nil {
			exePath = os.Args[0]
		}
		dnscryptExe := filepath.Join(filepath.Dir(exePath), "dnscrypt-proxy.exe")
		if _, statErr := os.Stat(dnscryptExe); os.IsNotExist(statErr) {
			err = fmt.Errorf("dnscrypt-proxy.exe not found at %s", dnscryptExe)
			serviceError = services.ErrorDNSCryptClient
			return
		}

		// Write TOML config to the tunnel config directory alongside the JSON config
		tomlContent := dnsCryptConfig.GenerateTOML()
		configDir, dirErr := conf.TunnelConfigurationsDirectory()
		if dirErr != nil {
			err = fmt.Errorf("failed to get tunnel config directory: %w", dirErr)
			serviceError = services.ErrorDNSCryptClient
			return
		}
		tomlPath := filepath.Join(configDir, "dnscrypt-proxy-"+config.Name+".toml")
		if writeErr := os.WriteFile(tomlPath, []byte(tomlContent), 0o600); writeErr != nil {
			err = fmt.Errorf("failed to write dnscrypt-proxy.toml: %w", writeErr)
			serviceError = services.ErrorDNSCryptClient
			return
		}

		dnscryptArgs := []string{"-config", tomlPath}
		dnscryptCmd = exec.Command(dnscryptExe, dnscryptArgs...)
		dnscryptCmd.Dir = filepath.Dir(dnscryptExe)
		dnscryptCmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
		// Redirect dnscrypt-proxy output to a log file so it is visible when
		// running as a SYSTEM service (which has no console).
		logPath := filepath.Join(configDir, "dnscrypt-proxy-"+config.Name+".log")
		if logFile, openErr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); openErr == nil {
			dnscryptCmd.Stdout = logFile
			dnscryptCmd.Stderr = logFile
		}

		// Note: we no longer override config.Interface.DNS automatically.
		// The user is responsible for setting the tunnel DNS to the local
		// proxy address (e.g. 127.0.0.1:53) in the WireGuard configuration
		// if they want DNS traffic to go through dnscrypt-proxy.
		dnscryptListenAddr, _, _ = strings.Cut(dnsCryptConfig.ListenAddress, ":")
	}

	// Check and start DNS router if configured
	dnsRouterConfig, dnsRouterErr := conf.LoadDNSRouterConfig(config.Name)
	var wgIPChan chan net.IP
	if dnsRouterErr == nil && dnsRouterConfig.Enabled {
		log.Println("Starting DNS router")
		// Determine dnscrypt upstream address
		dnscryptUpstream = ""
		if dnscryptListenAddr != "" {
			dnscryptUpstream = dnsCryptConfig.ListenAddress
		}
		wgIPChan = make(chan net.IP, 100)
		// Determine the DNS router listen address.
		routerHost, _, _ := strings.Cut(dnsRouterConfig.ListenAddress, ":")
		if routerHost == "" {
			routerHost = "127.0.0.1"
		}
		routerAddr, parseErr := netip.ParseAddr(routerHost)
		if parseErr == nil {
			originalDNS = make([]netip.Addr, len(config.Interface.DNS))
			copy(originalDNS, config.Interface.DNS)
			config.Interface.DNS = []netip.Addr{routerAddr}
			log.Printf("Redirecting tunnel DNS to DNS router at %s", routerAddr)
		} else {
			log.Printf("Warning: could not parse DNS router listen address %q: %v", dnsRouterConfig.ListenAddress, parseErr)
		}
		// Override physical adapter DNS so all system DNS queries are forced
		// through the DNS router regardless of interface routing.
		var overrideErr error
		physicalDNSOverrides, originalServers, overrideErr = winipcfg.OverridePhysicalDNS([]netip.Addr{routerAddr})
		if overrideErr != nil {
			log.Printf("Warning: failed to override physical adapter DNS: %v", overrideErr)
		} else {
			log.Printf("Overridden %d physical adapter(s) DNS to %s", len(physicalDNSOverrides), routerAddr)
		}
		// DNS router will be started after the interface is UP so it can bind WG IPs.
	}

	log.Println("Creating network adapter")
	for i := range 15 {
		if i > 0 {
			time.Sleep(time.Second)
			log.Printf("Retrying adapter creation after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
		}
		adapter, err = driver.CreateAdapter(config.Name, "WireGuard", deterministicGUID(config))
		if err == nil || !services.StartedAtBoot() {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("Error creating adapter: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return
	}
	luid = adapter.LUID()
	driverVersion, err := driver.RunningVersion()
	if err != nil {
		log.Printf("Warning: unable to determine driver version: %v", err)
	} else {
		log.Printf("Using WireGuardNT/%d.%d", (driverVersion>>16)&0xffff, driverVersion&0xffff)
	}
	err = adapter.SetLogging(driver.AdapterLogOn)
	if err != nil {
		err = fmt.Errorf("Error enabling adapter logging: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return
	}

	err = runScriptCommand(config.Interface.PreUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	err = enableFirewall(config, luid)
	if err != nil {
		serviceError = services.ErrorFirewall
		return
	}

	log.Println("Dropping privileges")
	err = elevate.DropAllPrivileges(true)
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return
	}

	log.Println("Setting interface configuration")
	err = adapter.SetConfiguration(config.ToDriverConfiguration())
	if err != nil {
		serviceError = services.ErrorDeviceSetConfig
		return
	}
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		serviceError = services.ErrorDeviceBringUp
		return
	}

	// Start DNSCrypt proxy after interface is UP so it can bind WG IPs.
	if dnscryptCmd != nil {
		if cmdErr := dnscryptCmd.Start(); cmdErr != nil {
			err = fmt.Errorf("failed to start dnscrypt-proxy: %w", cmdErr)
			serviceError = services.ErrorDNSCryptClient
			return
		}
		dnscryptProcess = dnscryptCmd.Process
		log.Println("DNSCrypt proxy started")
	}

	// Start DNS router after interface is UP so it can bind WG IPs.
	if dnsRouterErr == nil && dnsRouterConfig != nil && dnsRouterConfig.Enabled {
		log.Println("Starting DNS router")
		var routerErr error
		dnsRouterInst, routerErr = startDNSRouter(config.Name, dnscryptUpstream, originalServers, wgIPChan)
		if routerErr != nil {
			err = routerErr
			serviceError = services.ErrorDNSRouter
			return
		}
	}

	// Start syncer if DNS router is active (after interface is UP)
	if wgIPChan != nil {
		if dnsRouterConfig.Mode == conf.DNSRouterModeRouteTable {
			// Prevent WG from adding default routes; we control routing via /32 entries.
			config.Interface.TableOff = true
			routeSyncer = newRouteTableSyncer(luid, dnsRouterConfig.TTLMinutes)
			routeSyncer.Start()
			// Add /32 (v4) and /128 (v6) AllowedIPs to the route table as host routes.
			for _, peer := range config.Peers {
				for _, prefix := range peer.AllowedIPs {
					if prefix.IsSingleIP() {
						routeSyncer.AddIP(prefix.Addr())
					}
				}
			}
			go func() {
				for ip := range wgIPChan {
					if addr, ok := netip.AddrFromSlice(ip.To4()); ok {
						routeSyncer.AddIP(addr)
					}
				}
			}()
			log.Println("Route table syncer started")
		} else {
			ipSyncer = newAllowedIPsSyncer(adapter, config, dnsRouterConfig.TTLMinutes)
			ipSyncer.Start()
			go func() {
				for ip := range wgIPChan {
					if addr, ok := netip.AddrFromSlice(ip.To4()); ok {
						ipSyncer.AddIP(addr)
					}
				}
			}()
			log.Println("AllowedIPs syncer started")
		}
	}

	watcher.Configure(adapter, config, luid)

	err = runScriptCommand(config.Interface.PostUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	var started bool
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d\n", c)
			}
		case <-watcher.started:
			if !started {
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				log.Println("Startup complete")
				started = true
			}
		case e := <-watcher.errors:
			serviceError, err = e.serviceError, e.err
			return
		}
	}
}

func Run(confPath string) error {
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		return err
	}
	serviceName, err := conf.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	return svc.Run(serviceName, &tunnelService{confPath})
}

func parsePhantunLocalPort(local string) uint16 {
	_, portStr, found := strings.Cut(local, ":")
	if !found {
		return 8080
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 8080
	}
	return uint16(port)
}
