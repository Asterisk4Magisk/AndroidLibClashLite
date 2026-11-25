// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package api

import (
	"encoding/json"
	"time"

	"cfa/native/controlauth"
	"cfa/native/dnsevents"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/hub/route"
)

func init() {
	route.Register(func(r chi.Router) {
		r.Get(dnsevents.Path, handle)
	})
}

func handle(w http.ResponseWriter, r *http.Request) {
	if !controlauth.RequireLocalToken(w, r) {
		return
	}
	events, unsubscribe := dnsevents.Subscribe()
	defer unsubscribe()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	controller := http.NewResponseController(w)
	if controller.Flush() != nil {
		return
	}
	encoder := json.NewEncoder(w)
	const flushInterval = 100 * time.Millisecond
	timer := time.NewTimer(flushInterval)
	timer.Stop()
	defer timer.Stop()
	var flushAt <-chan time.Time
	for {
		select {
		case <-r.Context().Done():
			return
		case <-flushAt:
			flushAt = nil
			if controller.Flush() != nil {
				return
			}
		case event := <-events:
			if encoder.Encode(event) != nil {
				return
			}
			if flushAt == nil {
				timer.Reset(flushInterval)
				flushAt = timer.C
			}
		}
	}
}
