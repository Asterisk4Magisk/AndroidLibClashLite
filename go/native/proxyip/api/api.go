// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"net"

	"cfa/native/controlauth"
	"cfa/native/proxyip"
	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/tunnel"
)

func init() {
	route.Register(func(r chi.Router) {
		r.Post("/asterisk/proxy-ip-probe", handle)
	})
}

func handle(w http.ResponseWriter, r *http.Request) {
	if !controlauth.RequireLocalToken(w, r) {
		return
	}
	body := http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request proxyip.Request
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !request.Valid() {
		replyError(w, r, http.StatusBadRequest, "INVALID_ARGUMENT")
		return
	}
	outbound, runtime := tunnel.ProxyIPProbeTarget(request.OutboundTag)
	if runtime == nil {
		replyError(w, r, http.StatusConflict, "NOT_RUNNING")
		return
	}
	if outbound == nil || !isGroup(outbound.Type()) {
		replyError(w, r, http.StatusNotFound, "OUTBOUND_NOT_FOUND")
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer context.AfterFunc(runtime, cancel)()
	result := proxyip.Measure(ctx, request, func(ctx context.Context, address string) (net.Conn, error) {
		metadata := &C.Metadata{NetWork: C.TCP, Type: C.INNER, DNSMode: C.DNSNormal}
		if err := metadata.SetRemoteAddress(address); err != nil {
			return nil, err
		}
		return outbound.DialContext(ctx, metadata)
	}, nil)
	if r.Context().Err() != nil {
		return
	}
	if runtime.Err() != nil {
		replyError(w, r, http.StatusConflict, "RUNTIME_CHANGED")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	render.JSON(w, r, result)
}

func isGroup(kind C.AdapterType) bool {
	switch kind {
	case C.Selector, C.URLTest, C.Fallback, C.LoadBalance:
		return true
	default:
		return false
	}
}

func replyError(w http.ResponseWriter, r *http.Request, status int, code string) {
	render.Status(r, status)
	render.JSON(w, r, map[string]string{"code": code})
}
