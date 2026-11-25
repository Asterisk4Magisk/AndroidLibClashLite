// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package controlauth

import (
	"net"

	"cfa/native/proxyip"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
)

// RequireLocalToken authenticates local controller extensions using the core's token.
func RequireLocalToken(w http.ResponseWriter, r *http.Request) bool {
	_, unix := r.Context().Value(http.LocalAddrContextKey).(*net.UnixAddr)
	if (unix || proxyip.Loopback(r.RemoteAddr)) &&
		proxyip.ValidToken(C.Path.HomeDir(), r.Header.Get(proxyip.TokenHeader)) {
		return true
	}
	render.Status(r, http.StatusForbidden)
	render.JSON(w, r, map[string]string{"code": "PERMISSION_DENIED"})
	return false
}
