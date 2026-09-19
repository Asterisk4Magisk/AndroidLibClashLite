package config

import "github.com/metacubex/mihomo/component/age"

func SetGlobalSecretKeys(secretKeys ...string) {
	age.SetGlobalSecretKeys(secretKeys...)
}

func DecryptBytes(data []byte, secretKeys ...string) ([]byte, error) {
	return age.DecryptBytes(data, secretKeys...)
}

func VeritySecretKeys(secretKeys ...string) error {
	return age.VeritySecretKeys(secretKeys...)
}
