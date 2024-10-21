/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type BifrostConfigT struct {
	Listener       ListenerT       `yaml:"listener"`
	Authentication AuthenticationT `yaml:"authentication"`
	Modifiers      []ModifierT     `yaml:"modifiers"`
	Target         TargetT         `yaml:"target"`
}

type ListenerT struct {
	Port    string           `yaml:"port"`
	Host    string           `yaml:"host"`
	Options ListenerOptionsT `yaml:"options"`
}

type ListenerOptionsT struct {
	ReadTimeout              string `yaml:"readTimeout"`
	WriteTimeout             string `yaml:"writeTimeout"`
	MaxConcurrentConnections int    `yaml:"maxConcurrentConnections"`

	// Carry stuff
	ReadTimeoutDuration  *time.Duration
	WriteTimeoutDuration *time.Duration
}

type AuthenticationT struct {
	BucketCredentials []BucketCredentialT `yaml:"bucketCredentials"`
	ClientCredentials ClientCredentialsT  `yaml:"clientCredentials"`
}

type BucketCredentialT struct {
	Name            string `yaml:"name"`
	AccessKeyId     string `yaml:"accessKeyId"`
	SecretAccessKey string `yaml:"secretAccessKey"`
	Region          string `yaml:"region"`

	// Carry stuff
	AwsConfig *aws.Config
}

type ClientCredentialsT struct {
	Type string                 `yaml:"type"`
	None NoneClientCredentialsT `yaml:"none,omitempty"`
	S3   S3ClientCredentialsT   `yaml:"s3,omitempty"`
}

type BucketCredentialRefT struct {
	Name string `yaml:"name"`
}

type NoneClientCredentialsT struct {
	BucketCredentialRef BucketCredentialRefT `yaml:"bucketCredentialRef"`
}

type S3ClientCredentialsT struct {
	SignatureVerification bool `yaml:"signatureVerification"`
}

type ModifierT struct {
	Type string        `yaml:"type"`
	Path ModifierPathT `yaml:"path"`
}

type ModifierPathT struct {
	Pattern string `yaml:"pattern"`
	Replace string `yaml:"replace"`

	// Carry stuff
	CompiledRegex *regexp.Regexp
}

type TargetT struct {
	Scheme  string         `yaml:"scheme"`
	Port    string         `yaml:"port"`
	Host    string         `yaml:"host"`
	Tls     TargetTlsT     `yaml:"tls"`
	Options TargetOptionsT `yaml:"options"`
}

type TargetTlsT struct {
	SkipVerify bool `yaml:"skipVerify"`
}

type TargetOptionsT struct {
	DialTimeout string `yaml:"dialTimeout"`
	KeepAlive   string `yaml:"keepAlive"`

	// Carry stuff
	DialTimeoutDuration *time.Duration
	KeepAliveDuration   *time.Duration
}
