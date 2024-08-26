package config

import (
	"bifrost/api"
	"os"

	"gopkg.in/yaml.v3"
)

// Marshal TODO
func Marshal(config api.BifrostConfigT) (bytes []byte, err error) {
	bytes, err = yaml.Marshal(config)
	return bytes, err
}

// Unmarshal TODO
func Unmarshal(bytes []byte) (config api.BifrostConfigT, err error) {
	err = yaml.Unmarshal(bytes, &config)
	return config, err
}

// ReadFile TODO
func ReadFile(filepath string) (config api.BifrostConfigT, err error) {
	var fileBytes []byte
	fileBytes, err = os.ReadFile(filepath)
	if err != nil {
		return config, err
	}

	fileBytes = []byte(os.ExpandEnv(string(fileBytes)))

	config, err = Unmarshal(fileBytes)

	return config, err
}
