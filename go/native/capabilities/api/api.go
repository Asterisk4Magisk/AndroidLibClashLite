// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package api

import (
	"cfa/native/capabilities"
	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/hub/route"
)

func init() {
	route.Register(func(r chi.Router) {
		r.Get("/asterisk/capabilities", func(w http.ResponseWriter, r *http.Request) {
			render.JSON(w, r, capabilities.Snapshot())
		})
	})
}
