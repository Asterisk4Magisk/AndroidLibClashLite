//go:build android && cmfa

package libclash

import (
	"strings"

	"github.com/metacubex/mihomo/dns"
)

// NotifyDnsChanged replaces Android's underlying-network DNS servers. Entries
// are comma-separated IP:port endpoints, with brackets around IPv6 addresses.
// An empty list removes servers from networks that are no longer available.
func NotifyDnsChanged(dnsList string) {
	var servers []string
	for _, entry := range strings.Split(dnsList, ",") {
		if server := strings.TrimSpace(entry); server != "" {
			servers = append(servers, server)
		}
	}
	dns.UpdateSystemDNS(servers)
	dns.FlushCacheWithDefaultResolver()
}
