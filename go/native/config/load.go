// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package config

import (
	"fmt"
	"os"
	P "path"
	"path/filepath"
	"runtime"
	"strings"

	"cfa/native/app"

	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
)

func logDns(cfg *config.RawConfig) {
	bytes, err := yaml.Marshal(&cfg.DNS)
	if err != nil {
		log.Warnln("Marshal dns: %s", err.Error())

		return
	}

	log.Infoln("dns:")

	for _, line := range strings.Split(string(bytes), "\n") {
		log.Infoln("  %s", line)
	}
}

func UnmarshalAndPatch(profilePath string) (*config.RawConfig, error) {
	configPath := P.Join(profilePath, "config.yaml")

	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	return UnmarshalAndPatchBytes(profilePath, configData)
}

func UnmarshalAndPatchBytes(profilePath string, configData []byte) (*config.RawConfig, error) {
	rawConfig, err := config.UnmarshalRawConfig(configData)
	if err != nil {
		return nil, err
	}

	if err := process(rawConfig, profilePath); err != nil {
		return nil, err
	}

	return rawConfig, nil
}

func Parse(rawConfig *config.RawConfig) (*config.Config, error) {
	cfg, err := config.ParseRawConfig(rawConfig)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func Load(path string) error {
	rawCfg, err := UnmarshalAndPatch(path)
	return applyProfile(path, rawCfg, err, hub.ApplyConfig)
}

// LoadBytes keeps standby configuration in memory without replacing the service's config.yaml.
// path remains the provider base directory, just as it is for Load.
func LoadBytes(path string, content []byte) error {
	rawCfg, err := UnmarshalAndPatchBytes(path, content)
	return applyProfile(path, rawCfg, err, hub.ApplyConfig)
}

// Reload applies an HTTP configuration update through the same preparation as
// JNI Load, retaining the running controller and the separately owned VPN TUN.
// A nil content reads path; otherwise path supplies the provider base directory.
func Reload(path string, content []byte, force bool) error {
	if content == nil {
		var err error
		content, err = os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(content) == 0 {
			return fmt.Errorf("configuration file %s is empty", path)
		}
	}
	profileDir := filepath.Dir(path)
	rawCfg, err := UnmarshalAndPatchBytes(profileDir, content)
	return applyProfile(profileDir, rawCfg, err, func(cfg *config.Config) {
		executor.ApplyConfig(cfg, force)
	})
}

func applyProfile(path string, rawCfg *config.RawConfig, err error, apply func(*config.Config)) error {
	if err != nil {
		log.Errorln("Load %s: %s", path, err.Error())

		return err
	}

	logDns(rawCfg)

	cfg, err := Parse(rawCfg)
	if err != nil {
		log.Errorln("Load %s: %s", path, err.Error())

		return err
	}

	apply(cfg)

	app.ApplySubtitlePattern(rawCfg.ClashForAndroid.UiSubtitlePattern)

	runtime.GC()

	return nil
}

func LoadDefault() {
	cfg, err := config.Parse([]byte{})
	if err != nil {
		panic(err.Error())
	}

	hub.ApplyConfig(cfg)
}
