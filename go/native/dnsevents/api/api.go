// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package api

import (
	"encoding/json"
	"time"

	"cfa/native/controlauth"
	"cfa/native/dnsevents"
	"cfa/native/dnsevents/owner"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/tunnel"
)

func init() {
	owner.SetProcessModeReader(tunnel.FindProcessMode)
	route.Register(func(r chi.Router) {
		r.Get(dnsevents.Path, handle)
	})
}

func handle(w http.ResponseWriter, r *http.Request) {
	if !controlauth.RequireLocalToken(w, r) {
		return
	}
	history, events, unsubscribe, ok := dnsevents.Subscribe()
	if !ok {
		http.Error(w, "DNS events are unavailable", http.StatusServiceUnavailable)
		return
	}
	defer unsubscribe()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	controller := http.NewResponseController(w)
	if controller.Flush() != nil {
		return
	}
	encoder := json.NewEncoder(w)
	for _, event := range history {
		if r.Context().Err() != nil || encoder.Encode(event) != nil {
			return
		}
	}
	if len(history) != 0 && controller.Flush() != nil {
		return
	}
	history = nil
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
		case event, ok := <-events:
			if !ok || encoder.Encode(event) != nil {
				return
			}
			if flushAt == nil {
				timer.Reset(flushInterval)
				flushAt = timer.C
			}
		}
	}
}
