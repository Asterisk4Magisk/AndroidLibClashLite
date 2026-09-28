package app

import (
	"sync/atomic"

	"github.com/dlclark/regexp2"

	"github.com/metacubex/mihomo/log"
)

var uiSubtitlePattern atomic.Pointer[regexp2.Regexp]

func ApplySubtitlePattern(pattern string) {
	if pattern == "" {
		uiSubtitlePattern.Store(nil)

		return
	}

	if o := uiSubtitlePattern.Load(); o != nil && o.String() == pattern {
		return
	}

	reg, err := regexp2.Compile(pattern, regexp2.IgnoreCase|regexp2.Compiled)
	if err == nil {
		uiSubtitlePattern.Store(reg)
	} else {
		uiSubtitlePattern.Store(nil)

		log.Warnln("Compile ui-subtitle-pattern: %s", err.Error())
	}
}

func SubtitlePattern() *regexp2.Regexp {
	return uiSubtitlePattern.Load()
}
