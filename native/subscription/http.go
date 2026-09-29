// Package subscription downloads subscriptions with request-scoped identity.
package subscription

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/ca"
)

var hwidPattern = regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`)

// Get returns only successful configuration responses. The caller owns Body.
// An empty hwid preserves anonymous/provider requests. Identity never crosses origins.
func Get(ctx context.Context, rawURL, userAgent, hwid string, dial func(context.Context, string, string) (net.Conn, error)) (*http.Response, error) {
	if hwid != "" && !hwidPattern.MatchString(hwid) {
		return nil, errors.New("HWID_INVALID")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("invalid subscription URL")
	}
	req.Header.Set("User-Agent", userAgent)
	if hwid != "" {
		req.Header.Set("X-Hwid", hwid)
	}
	if user := req.URL.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
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
	client := http.Client{Transport: transport, CheckRedirect: checkRedirect}
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

func checkRedirect(req *http.Request, via []*http.Request) error {
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
			req.Header.Del("X-Hwid")
			req.Header.Del("Authorization")
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
