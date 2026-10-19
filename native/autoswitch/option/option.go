// Package option holds the asterisk-auto-switch schema. It depends only on leaf
// packages so the patched upstream config package can embed it.
package option

import (
	"errors"
	"strings"

	"github.com/dlclark/regexp2"

	"github.com/metacubex/mihomo/common/utils"
)

const (
	DefaultFailureThreshold = 1
	DefaultIntervalSeconds  = 30
	DefaultTimeoutMillis    = 5000
	DefaultConcurrency      = 5
	DefaultURL              = "https://www.gstatic.com/generate_204"
)

// Settings is read from the top-level `asterisk-auto-switch` key and accepted by
// the hot-update APIs. Field names follow Mihomo proxy-group health-check options.
type Settings struct {
	Enable           bool     `yaml:"enable" json:"enable"`
	Groups           []string `yaml:"groups" json:"groups"`
	PreferredFilter  string   `yaml:"preferred-filter" json:"preferred-filter"`
	FailureThreshold int      `yaml:"failure-threshold" json:"failure-threshold"`
	ExpectedDelay    int      `yaml:"expected-delay" json:"expected-delay"`
	Interval         int      `yaml:"interval" json:"interval"`
	URL              string   `yaml:"url" json:"url"`
	Timeout          int      `yaml:"timeout" json:"timeout"`
	ExpectedStatus   string   `yaml:"expected-status" json:"expected-status"`
	Concurrency      int      `yaml:"concurrency" json:"concurrency"`
}

// Normalized fills defaults and clamps ranges. It never fails; use Validate for
// values supplied through a control API.
func (s Settings) Normalized() Settings {
	groups := make([]string, 0, len(s.Groups))
	seen := make(map[string]struct{}, len(s.Groups))
	for _, group := range s.Groups {
		group = strings.TrimSpace(group)
		if _, ok := seen[group]; ok || group == "" {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	s.Groups = groups
	s.FailureThreshold = clamp(s.FailureThreshold, DefaultFailureThreshold, 1, 10)
	s.ExpectedDelay = min(max(s.ExpectedDelay, 0), 99999)
	s.Interval = clamp(s.Interval, DefaultIntervalSeconds, 10, 3600)
	s.Timeout = clamp(s.Timeout, DefaultTimeoutMillis, 1000, 30000)
	s.Concurrency = clamp(s.Concurrency, DefaultConcurrency, 1, 32)
	if s.URL = strings.TrimSpace(s.URL); s.URL == "" {
		s.URL = DefaultURL
	}
	return s
}

// Validate rejects values that Normalized would otherwise silently disable.
func (s Settings) Validate() error {
	if s.ExpectedDelay < 0 || s.ExpectedDelay > 99999 {
		return errors.New("expected-delay must be between 0 and 99999 ms")
	}
	if _, err := s.CompileFilter(); err != nil {
		return err
	}
	if _, err := utils.NewUnsignedRanges[uint16](s.ExpectedStatus); err != nil {
		return err
	}
	if s.Enable && len(s.Normalized().Groups) == 0 {
		return errors.New("at least one group is required")
	}
	return nil
}

// CompileFilter returns nil when no preferred filter is configured.
func (s Settings) CompileFilter() (*regexp2.Regexp, error) {
	if s.PreferredFilter == "" {
		return nil, nil
	}
	return regexp2.Compile(s.PreferredFilter, regexp2.None)
}

func clamp(value, fallback, low, high int) int {
	if value == 0 {
		return fallback
	}
	return min(max(value, low), high)
}
