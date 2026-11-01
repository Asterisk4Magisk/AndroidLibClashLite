// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

// Package api adds the app's embedded config mutations to the Unix controller.
// The standalone CLI keeps upstream's full configuration API.
package api

import (
	"encoding/json"
	"path/filepath"

	"cfa/environment"
	"cfa/native/config"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

func init() {
	if environment.IsCLI {
		return
	}
	route.Register(func(r chi.Router) {
		for _, path := range []string{"/configs", "/configs/"} {
			r.Patch(path, patchConfigs)
			r.Put(path, updateConfigs)
		}
	})
}

func patchConfigs(w http.ResponseWriter, r *http.Request) {
	// Upstream PATCH also recreates listeners and its TUN. Embedded mode only
	// accepts the app's runtime mutations, leaving the JNI-owned TUN untouched.
	var settings struct {
		Mode     *tunnel.TunnelMode `json:"mode"`
		LogLevel *log.LogLevel      `json:"log-level"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		badRequest(w, r, route.ErrBadRequest)
		return
	}
	if settings.Mode != nil {
		tunnel.SetMode(*settings.Mode)
	}
	if settings.LogLevel != nil {
		log.SetLevel(*settings.LogLevel)
	}
	render.NoContent(w, r)
}

func updateConfigs(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Path    string `json:"path"`
		Payload string `json:"payload"`
	}
	if err := render.DecodeJSON(r.Body, &request); err != nil {
		badRequest(w, r, route.ErrBadRequest)
		return
	}
	if request.Path == "" {
		request.Path = C.Path.Config()
	} else if request.Payload == "" {
		if !filepath.IsAbs(request.Path) {
			badRequest(w, r, &route.HTTPError{Message: "path is not a absolute path"})
			return
		}
		if !C.Path.IsSafePath(request.Path) {
			badRequest(w, r, &route.HTTPError{Message: C.Path.ErrNotSafePath(request.Path).Error()})
			return
		}
	}
	var content []byte
	if request.Payload != "" {
		content = []byte(request.Payload)
	}
	if err := config.Reload(request.Path, content, r.URL.Query().Get("force") == "true"); err != nil {
		badRequest(w, r, &route.HTTPError{Message: err.Error()})
		return
	}
	render.NoContent(w, r)
}

func badRequest(w http.ResponseWriter, r *http.Request, err *route.HTTPError) {
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, err)
}
