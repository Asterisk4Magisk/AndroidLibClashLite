// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

// Package subscription downloads subscriptions with request-scoped identity.
package subscription

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/ca"
	"golang.org/x/net/http/httpguts"
)

// Get returns only successful configuration responses. The caller owns Body.
// Request headers and URL credentials are scoped to the initial origin.
func Get(ctx context.Context, rawURL, userAgent string, requestHeaders map[string]string, dial func(context.Context, string, string) (net.Conn, error)) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("invalid subscription URL")
	}
	req.Header.Set("User-Agent", userAgent)
	if user := req.URL.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}
	scopedHeaders := []string{"Authorization"}
	for name, value := range requestHeaders {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return nil, errors.New("invalid subscription request header")
		}
		switch strings.ToLower(name) {
		case "host", "connection", "content-length", "transfer-encoding", "proxy-authorization",
			"if-none-match", "if-modified-since", "user-agent", "x-age-public-key":
			return nil, errors.New("managed subscription request header")
		}
		req.Header.Set(name, value)
		scopedHeaders = append(scopedHeaders, name)
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DisableKeepAlives:     true,
		DialContext:           dial,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return checkRedirect(req, via, scopedHeaders)
	}}
	response, err := client.Do(req)
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			return nil, urlError.Err
		}
		return nil, err
	}
	// Servers may send a 200 denial body. Never expose that body to config parsing.
	switch {
	case strings.EqualFold(response.Header.Get("x-hwid-max-devices-reached"), "true"), strings.EqualFold(response.Header.Get("x-hwid-limit"), "true"):
		err = errors.New("HWID_LIMIT_REACHED")
	case strings.EqualFold(response.Header.Get("x-hwid-not-supported"), "true"):
		err = errors.New("HWID_NOT_SUPPORTED")
	case response.StatusCode < 200 || response.StatusCode >= 300:
		err = fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if err != nil {
		response.Body.Close()
		return nil, err
	}
	return response, nil
}

func checkRedirect(req *http.Request, via []*http.Request, scopedHeaders []string) error {
	if len(via) >= 10 {
		return errors.New("too many subscription redirects")
	}
	previous := via[len(via)-1]
	if previous.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("subscription HTTPS downgrade blocked")
	}
	// Check the entire chain: an A -> B -> A redirect must not restore identity.
	for _, prior := range via {
		if !sameOrigin(prior.URL, req.URL) {
			for _, name := range scopedHeaders {
				req.Header.Del(name)
			}
			break
		}
	}
	return nil
}

func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}
