// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

// Package api exposes auto-switch through the authenticated Clash API as
// GET/PATCH /asterisk/auto-switch. Import it for its registration side effect;
// it is separate from autoswitch because hub/route depends on the executor hook.
package api

import (
	"cfa/native/autoswitch"
	"cfa/native/autoswitch/option"

	"github.com/metacubex/mihomo/hub/route"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

const Path = "/asterisk/auto-switch"

func init() {
	route.Register(func(r chi.Router) {
		r.Get(Path, getState)
		r.Patch(Path, patchSettings)
	})
}

func getState(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, autoswitch.Snapshot())
}

func patchSettings(w http.ResponseWriter, r *http.Request) {
	var settings option.Settings
	if err := render.DecodeJSON(r.Body, &settings); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, route.ErrBadRequest)
		return
	}
	if err := autoswitch.Patch(settings); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, &route.HTTPError{Message: err.Error()})
		return
	}
	render.NoContent(w, r)
}
