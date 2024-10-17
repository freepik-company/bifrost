package config

import (
	"bifrost/api"
	"bifrost/internal/globals"
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"gopkg.in/yaml.v3"
)

// unmarshal performs the unmarshalling of the configuration file
func unmarshal(bytes []byte) (config api.BifrostConfigT, err error) {
	err = yaml.Unmarshal(bytes, &config)
	return config, err
}

// ReadFile reads the configuration file and returns the parsed configuration
func ReadFile(filepath string) (config api.BifrostConfigT, err error) {
	var fileBytes []byte
	fileBytes, err = os.ReadFile(filepath)
	if err != nil {
		return config, err
	}

	fileBytes = []byte(os.ExpandEnv(string(fileBytes)))

	config, err = unmarshal(fileBytes)

	return config, err
}

// Init performs the initialization of the configuration carried fields
func Init() error {
	listenerReadTimeoutDuration, err := time.ParseDuration(globals.Application.Config.Listener.Options.ReadTimeout)
	if err != nil {
		return fmt.Errorf("unable to parse listener read timeout duration")
	}

	globals.Application.Config.Listener.Options.ReadTimeoutDuration = &listenerReadTimeoutDuration

	// TODO
	listenerWriteTimeoutDuration, err := time.ParseDuration(globals.Application.Config.Listener.Options.WriteTimeout)
	if err != nil {
		return fmt.Errorf("unable to parse listener write timeout duration")
	}

	globals.Application.Config.Listener.Options.WriteTimeoutDuration = &listenerWriteTimeoutDuration

	// TODO
	targetDialTimeoutDuration, err := time.ParseDuration(globals.Application.Config.Target.Options.DialTimeout)
	if err != nil {
		return fmt.Errorf("unable to parse target dial timeout duration")
	}

	globals.Application.Config.Target.Options.DialTimeoutDuration = &targetDialTimeoutDuration

	// TODO
	targetKeepAliveDuration, err := time.ParseDuration(globals.Application.Config.Target.Options.KeepAlive)
	if err != nil {
		return fmt.Errorf("unable to parse target keep-alive duration")
	}

	globals.Application.Config.Target.Options.KeepAliveDuration = &targetKeepAliveDuration

	// Prepare AWS config for each bucket credential
	for credentialIndex, credentialObj := range globals.Application.Config.Authentication.BucketCredentials {

		awsConfig, err := config.LoadDefaultConfig(context.TODO(),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				credentialObj.AccessKeyId, credentialObj.SecretAccessKey, "")),
			config.WithRegion(credentialObj.Region),
		)

		if err != nil {
			return fmt.Errorf("unable to prepare AWS config for bucket credential: %s", err.Error())
		}

		globals.Application.Config.Authentication.BucketCredentials[credentialIndex].AwsConfig = &awsConfig
	}

	//
	for index, mod := range globals.Application.Config.Modifiers {
		// Compile regex for path modifiers
		if mod.Type == "path" {
			globals.Application.Config.Modifiers[index].Path.CompiledRegex = regexp.MustCompile(mod.Path.Pattern)
		}
	}

	return nil
}
