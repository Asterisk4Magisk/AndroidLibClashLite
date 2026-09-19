package app

var appVersionName string
var platformVersion int
var installedAppsUid = map[int]string{}

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
	return installedAppsUid[uid]
}
