package app

import (
	"strconv"
	"strings"
	"sync/atomic"
)

var appVersionName string
var platformVersion int
var installedAppsUid atomic.Pointer[map[int]string]

func ApplyVersionName(versionName string) {
	appVersionName = versionName
}

func ApplyPlatformVersion(version int) {
	platformVersion = version
}

func VersionName() string {
	return appVersionName
}

func PlatformVersion() int {
	return platformVersion
}

func QueryAppByUid(uid int) string {
	if apps := installedAppsUid.Load(); apps != nil {
		return (*apps)[uid]
	}
	return ""
}

// NotifyInstallAppsChanged replaces the complete UID/package snapshot.
func NotifyInstallAppsChanged(uidList string) {
	apps := make(map[int]string)
	for _, item := range strings.Split(uidList, ",") {
		uidText, name, ok := strings.Cut(item, ":")
		if !ok || name == "" {
			continue
		}
		uid, err := strconv.Atoi(uidText)
		if err == nil && uid >= 0 {
			apps[uid] = name
		}
	}
	installedAppsUid.Store(&apps)
}
