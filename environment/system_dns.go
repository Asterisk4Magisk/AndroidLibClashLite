package environment

import "os"

// Only standalone ROOT owns a Java observer. JNI keeps the app's callbacks;
// non-root standalone invocations retain the native resolver implementation.
func ManagedSystemDNS() bool {
	return IsCLI && os.Geteuid() == 0
}
