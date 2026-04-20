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

	enabledCB   *walk.CheckBox
	remoteEdit  *walk.LineEdit
	localEdit   *walk.LineEdit
	saveButton  *walk.PushButton
	statusLabel *walk.TextLabel

	currentTunnel string
	config        *conf.PhantunConfig
}

func NewPhantunPage() (*PhantunPage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	pp := new(PhantunPage)
	pp.config = conf.DefaultPhantunConfig()

	if pp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(pp)

	pp.SetTitle(l18n.Sprintf("Obfuscation"))
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
	pp.statusLabel.SetText(l18n.Sprintf("Select a tunnel to configure phantun obfuscation."))

	row := 1

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
		pp.statusLabel.SetText(l18n.Sprintf("Select a tunnel to configure phantun obfuscation."))
		pp.enabledCB.SetEnabled(false)
		pp.remoteEdit.SetEnabled(false)
		pp.localEdit.SetEnabled(false)
		pp.saveButton.SetEnabled(false)
		return
	}

	pp.currentTunnel = tunnel.Name
	pp.enabledCB.SetEnabled(true)
	pp.remoteEdit.SetEnabled(true)
	pp.localEdit.SetEnabled(true)
	pp.saveButton.SetEnabled(true)
	pp.statusLabel.SetText(l18n.Sprintf("Configuring phantun for tunnel: %s", tunnel.Name))

	cfg, err := conf.LoadPhantunConfig(tunnel.Name)
	if err != nil {
		cfg = conf.DefaultPhantunConfig()
	}
	pp.config = cfg

	pp.enabledCB.SetChecked(cfg.Enabled)
	pp.remoteEdit.SetText(cfg.Remote)
	pp.localEdit.SetText(cfg.Local)

	pp.onEnabledChanged()
}

func (pp *PhantunPage) onEnabledChanged() {
	enabled := pp.enabledCB.Checked()
	pp.remoteEdit.SetEnabled(enabled)
	pp.localEdit.SetEnabled(enabled)
}

func (pp *PhantunPage) onSaveClicked() {
	if pp.currentTunnel == "" {
		return
	}

	pp.config.Enabled = pp.enabledCB.Checked()
	pp.config.Remote = strings.TrimSpace(pp.remoteEdit.Text())
	pp.config.Local = strings.TrimSpace(pp.localEdit.Text())

	if pp.config.Enabled && pp.config.Remote == "" {
		showWarningCustom(pp.Form(), l18n.Sprintf("Invalid configuration"), l18n.Sprintf("Remote server address is required when phantun is enabled."))
		return
	}

	err := pp.config.Save(pp.currentTunnel)
	if err != nil {
		showErrorCustom(pp.Form(), l18n.Sprintf("Unable to save phantun configuration"), err.Error())
		return
	}

	pp.statusLabel.SetText(l18n.Sprintf("Saved phantun configuration for %s", pp.currentTunnel))
}
