// Package environment restores the native CLI environment before Mihomo init.
// Android c-shared starts Go with an empty environment; JNI keeps its existing
// initialization unless the standalone launcher explicitly marks the process.
package environment

/*
#include <stdlib.h>
#include <string.h>
extern char **environ;
static int android_cli_process(void) {
    const char *mode = getenv("ANDROID_MIHOMO_CLI");
    return mode != NULL && strcmp(mode, "1") == 0;
}
static char *android_env_at(int index) { return environ[index]; }
*/
import "C"

import (
	"os"
	"strings"
)

// IsCLI is fixed before any Mihomo package is initialized.
var IsCLI = C.android_cli_process() != 0

func init() {
	if !IsCLI {
		return
	}
	var snapshot []string
	for i := C.int(0); ; i++ {
		entry := C.android_env_at(i)
		if entry == nil {
			break
		}
		snapshot = append(snapshot, C.GoString(entry))
	}
	for _, entry := range snapshot {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			if err := os.Setenv(key, value); err != nil {
				panic("cannot initialize Android CLI environment: " + err.Error())
			}
		}
	}
	_ = os.Unsetenv("ANDROID_MIHOMO_CLI")
	applyRuntimeLimits()
}
