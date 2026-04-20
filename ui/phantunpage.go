/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strings"

	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

type PhantunPage struct {
	*walk.TabPage

	// Phantun controls
	enabledCB   *walk.CheckBox
	remoteEdit  *walk.LineEdit
	localEdit   *walk.LineEdit

	// DNSCrypt controls
	dnsEnabledCB       *walk.CheckBox
	dnsListenEdit      *walk.LineEdit
	dnsServerNamesEdit *walk.LineEdit
	dnsCustomTOMLEdit  *walk.TextEdit

	saveButton  *walk.PushButton
	statusLabel *walk.TextLabel

	currentTunnel string
	phantunConfig *conf.PhantunConfig
	dnsCryptConfig *conf.DNSCryptConfig
}

func NewPhantunPage() (*PhantunPage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	pp := new(PhantunPage)
	pp.phantunConfig = conf.DefaultPhantunConfig()
	pp.dnsCryptConfig = conf.DefaultDNSCryptConfig()

	if pp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(pp)

	pp.SetTitle(l18n.Sprintf("Settings"))
	layout := walk.NewGridLayout()
	layout.SetSpacing(6)
	layout.SetMargins(walk.Margins{10, 10, 10, 10})
	layout.SetColumnStretchFactor(0, 0)
	layout.SetColumnStretchFactor(1, 1)
	pp.SetLayout(layout)

	pp.statusLabel, err = walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pp.statusLabel, walk.Rectangle{0, 0, 2, 1})
	pp.statusLabel.SetText(l18n.Sprintf("Select a tunnel to configure settings."))

	row := 1

	// ---- Phantun section ----
	phantunTitle, err := walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(phantunTitle, walk.Rectangle{0, row, 2, 1})
	phantunTitle.SetText(l18n.Sprintf("Phantun Obfuscation"))
	if boldFont, err := walk.NewFont("Segoe UI", 9, walk.FontBold); err == nil {
		phantunTitle.SetFont(boldFont)
	}
	row++

	pp.enabledCB, err = walk.NewCheckBox(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pp.enabledCB, walk.Rectangle{0, row, 2, 1})
	pp.enabledCB.SetText(l18n.Sprintf("Enable phantun obfuscation"))
	pp.enabledCB.SetEnabled(false)
	pp.enabledCB.CheckedChanged().Attach(pp.onEnabledChanged)
	row++

	remoteLabel, err := walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(remoteLabel, walk.Rectangle{0, row, 1, 1})
	remoteLabel.SetTextAlignment(walk.AlignHFarVCenter)
	remoteLabel.SetText(l18n.Sprintf("Remote server:"))

	pp.remoteEdit, err = walk.NewLineEdit(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pp.remoteEdit, walk.Rectangle{1, row, 1, 1})
	pp.remoteEdit.SetEnabled(false)
	row++

	localLabel, err := walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(localLabel, walk.Rectangle{0, row, 1, 1})
	localLabel.SetTextAlignment(walk.AlignHFarVCenter)
	localLabel.SetText(l18n.Sprintf("Local listen:"))

	pp.localEdit, err = walk.NewLineEdit(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pp.localEdit, walk.Rectangle{1, row, 1, 1})
	pp.localEdit.SetEnabled(false)
	pp.localEdit.SetText("127.0.0.1:8080")
	row++

	phantunInfo, err := walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(phantunInfo, walk.Rectangle{0, row, 2, 1})
	phantunInfo.SetText(l18n.Sprintf("When activated, all peer endpoints will be redirected to the local listen address above."))
	row++

	// Spacer between sections
	sectionSpacer, err := walk.NewVSpacer(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(sectionSpacer, walk.Rectangle{0, row, 2, 1})
	layout.SetRowStretchFactor(row, 0)
	row++

	// ---- DNSCrypt section ----
	dnsTitle, err := walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(dnsTitle, walk.Rectangle{0, row, 2, 1})
	dnsTitle.SetText(l18n.Sprintf("DNSCrypt Proxy"))
	if boldFont, err := walk.NewFont("Segoe UI", 9, walk.FontBold); err == nil {
		dnsTitle.SetFont(boldFont)
	}
	row++

	pp.dnsEnabledCB, err = walk.NewCheckBox(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pp.dnsEnabledCB, walk.Rectangle{0, row, 2, 1})
	pp.dnsEnabledCB.SetText(l18n.Sprintf("Enable DNSCrypt proxy"))
	pp.dnsEnabledCB.SetEnabled(false)
	pp.dnsEnabledCB.CheckedChanged().Attach(pp.onDNSEnabledChanged)
	row++

	dnsListenLabel, err := walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(dnsListenLabel, walk.Rectangle{0, row, 1, 1})
	dnsListenLabel.SetTextAlignment(walk.AlignHFarVCenter)
	dnsListenLabel.SetText(l18n.Sprintf("Local listen:"))

	pp.dnsListenEdit, err = walk.NewLineEdit(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pp.dnsListenEdit, walk.Rectangle{1, row, 1, 1})
	pp.dnsListenEdit.SetEnabled(false)
	pp.dnsListenEdit.SetText("127.0.0.1:53")
	row++

	dnsServersLabel, err := walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(dnsServersLabel, walk.Rectangle{0, row, 1, 1})
	dnsServersLabel.SetTextAlignment(walk.AlignHFarVCenter)
	dnsServersLabel.SetText(l18n.Sprintf("Server names:"))

	pp.dnsServerNamesEdit, err = walk.NewLineEdit(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pp.dnsServerNamesEdit, walk.Rectangle{1, row, 1, 1})
	pp.dnsServerNamesEdit.SetEnabled(false)
	row++

	dnsCustomLabel, err := walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(dnsCustomLabel, walk.Rectangle{0, row, 2, 1})
	dnsCustomLabel.SetText(l18n.Sprintf("Stamp or custom TOML:"))
	row++

	pp.dnsCustomTOMLEdit, err = walk.NewTextEdit(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pp.dnsCustomTOMLEdit, walk.Rectangle{0, row, 2, 1})
	pp.dnsCustomTOMLEdit.SetEnabled(false)
	row++

	dnsInfo, err := walk.NewTextLabel(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(dnsInfo, walk.Rectangle{0, row, 2, 1})
	dnsInfo.SetText(l18n.Sprintf("When activated, tunnel DNS will be redirected to the local DNSCrypt proxy."))
	row++

	// ---- Save button ----
	buttonsContainer, err := walk.NewComposite(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(buttonsContainer, walk.Rectangle{0, row, 2, 1})
	buttonsContainer.SetLayout(walk.NewHBoxLayout())
	buttonsContainer.Layout().SetMargins(walk.Margins{})

	walk.NewHSpacer(buttonsContainer)

	pp.saveButton, err = walk.NewPushButton(buttonsContainer)
	if err != nil {
		return nil, err
	}
	pp.saveButton.SetText(l18n.Sprintf("&Save"))
	pp.saveButton.SetEnabled(false)
	pp.saveButton.Clicked().Attach(pp.onSaveClicked)
	row++

	spacer, err := walk.NewVSpacer(pp)
	if err != nil {
		return nil, err
	}
	layout.SetRange(spacer, walk.Rectangle{0, row, 2, 1})
	layout.SetRowStretchFactor(row, 1)

	disposables.Spare()
	return pp, nil
}

func (pp *PhantunPage) SetTunnel(tunnel *manager.Tunnel) {
	if tunnel == nil {
		pp.currentTunnel = ""
		pp.statusLabel.SetText(l18n.Sprintf("Select a tunnel to configure settings."))
		pp.enabledCB.SetEnabled(false)
		pp.remoteEdit.SetEnabled(false)
		pp.localEdit.SetEnabled(false)
		pp.dnsEnabledCB.SetEnabled(false)
		pp.dnsListenEdit.SetEnabled(false)
		pp.dnsServerNamesEdit.SetEnabled(false)
		pp.dnsCustomTOMLEdit.SetEnabled(false)
		pp.saveButton.SetEnabled(false)
		return
	}

	pp.currentTunnel = tunnel.Name
	pp.enabledCB.SetEnabled(true)
	pp.remoteEdit.SetEnabled(true)
	pp.localEdit.SetEnabled(true)
	pp.dnsEnabledCB.SetEnabled(true)
	pp.dnsListenEdit.SetEnabled(true)
	pp.dnsServerNamesEdit.SetEnabled(true)
	pp.dnsCustomTOMLEdit.SetEnabled(true)
	pp.saveButton.SetEnabled(true)
	pp.statusLabel.SetText(l18n.Sprintf("Configuring settings for tunnel: %s", tunnel.Name))

	// Load Phantun config
	pcfg, err := manager.IPCClientLoadPhantunConfig(tunnel.Name)
	if err != nil {
		pcfg = conf.DefaultPhantunConfig()
	}
	pp.phantunConfig = pcfg
	pp.enabledCB.SetChecked(pcfg.Enabled)
	pp.remoteEdit.SetText(pcfg.Remote)
	pp.localEdit.SetText(pcfg.Local)
	pp.onEnabledChanged()

	// Load DNSCrypt config
	dcfg, err := manager.IPCClientLoadDNSCryptConfig(tunnel.Name)
	if err != nil {
		dcfg = conf.DefaultDNSCryptConfig()
	}
	pp.dnsCryptConfig = dcfg
	pp.dnsEnabledCB.SetChecked(dcfg.Enabled)
	pp.dnsListenEdit.SetText(dcfg.ListenAddress)
	pp.dnsServerNamesEdit.SetText(dcfg.ServerNames)
	pp.dnsCustomTOMLEdit.SetText(dcfg.CustomTOML)
	pp.onDNSEnabledChanged()
}

func (pp *PhantunPage) onEnabledChanged() {
	enabled := pp.enabledCB.Checked()
	pp.remoteEdit.SetEnabled(enabled)
	pp.localEdit.SetEnabled(enabled)
}

func (pp *PhantunPage) onDNSEnabledChanged() {
	enabled := pp.dnsEnabledCB.Checked()
	pp.dnsListenEdit.SetEnabled(enabled)
	pp.dnsServerNamesEdit.SetEnabled(enabled)
	pp.dnsCustomTOMLEdit.SetEnabled(enabled)
}

func (pp *PhantunPage) onSaveClicked() {
	if pp.currentTunnel == "" {
		return
	}

	// Save Phantun config
	pp.phantunConfig.Enabled = pp.enabledCB.Checked()
	pp.phantunConfig.Remote = strings.TrimSpace(pp.remoteEdit.Text())
	pp.phantunConfig.Local = strings.TrimSpace(pp.localEdit.Text())

	if pp.phantunConfig.Enabled && pp.phantunConfig.Remote == "" {
		showWarningCustom(pp.Form(), l18n.Sprintf("Invalid configuration"), l18n.Sprintf("Remote server address is required when phantun is enabled."))
		return
	}

	err := manager.IPCClientSavePhantunConfig(pp.currentTunnel, pp.phantunConfig)
	if err != nil {
		showErrorCustom(pp.Form(), l18n.Sprintf("Unable to save phantun configuration"), err.Error())
		return
	}

	// Save DNSCrypt config
	pp.dnsCryptConfig.Enabled = pp.dnsEnabledCB.Checked()
	pp.dnsCryptConfig.ListenAddress = strings.TrimSpace(pp.dnsListenEdit.Text())
	pp.dnsCryptConfig.ServerNames = strings.TrimSpace(pp.dnsServerNamesEdit.Text())
	pp.dnsCryptConfig.CustomTOML = strings.TrimSpace(pp.dnsCustomTOMLEdit.Text())

	if pp.dnsCryptConfig.Enabled && pp.dnsCryptConfig.ListenAddress == "" {
		showWarningCustom(pp.Form(), l18n.Sprintf("Invalid configuration"), l18n.Sprintf("Local listen address is required when DNSCrypt is enabled."))
		return
	}

	err = manager.IPCClientSaveDNSCryptConfig(pp.currentTunnel, pp.dnsCryptConfig)
	if err != nil {
		showErrorCustom(pp.Form(), l18n.Sprintf("Unable to save DNSCrypt configuration"), err.Error())
		return
	}

	pp.statusLabel.SetText(l18n.Sprintf("Saved settings for %s", pp.currentTunnel))
}
