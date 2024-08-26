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
	Listener  ListenerConfigT   `yaml:"listener"`
	Modifiers []ModifierConfigT `yaml:"modifiers"`
	Target    TargetConfigT     `yaml:"target"`
}

type ListenerConfigT struct {
	Port    string                 `yaml:"port"`
	Host    string                 `yaml:"host"`
	Options ListenerOptionsConfigT `yaml:"options"`
}

type ListenerOptionsConfigT struct {
	ReadTimeout  string `yaml:"readTimeout"`
	WriteTimeout string `yaml:"writeTimeout"`

	// Carry stuff
	ReadTimeoutDuration  *time.Duration
	WriteTimeoutDuration *time.Duration
}

type ModifierConfigT struct {
	Type      string                   `yaml:"type"`
	Path      ModifierPathConfigT      `yaml:"path"`
	Signature ModifierSignatureConfigT `yaml:"signature"`
}

type ModifierPathConfigT struct {
	Pattern string `yaml:"pattern"`
	Replace string `yaml:"replace"`

	// Carry stuff
	CompiledRegex *regexp.Regexp
}

type ModifierSignatureConfigT struct {
	Type    string `yaml:"type"`
	Version string `yaml:"version"`

	// Carry stuff
	AwsConfig *aws.Config
}

type TargetConfigT struct {
	Scheme  string               `yaml:"scheme"`
	Port    string               `yaml:"port"`
	Host    string               `yaml:"host"`
	Tls     TargetTlsConfigT     `yaml:"tls"`
	Options TargetOptionsConfigT `yaml:"options"`
}

type TargetTlsConfigT struct {
	SkipVerify bool `yaml:"skipVerify"`
}

type TargetOptionsConfigT struct {
	DialTimeout string `yaml:"dialTimeout"`
	KeepAlive   string `yaml:"keepAlive"`

	// Carry stuff
	DialTimeoutDuration *time.Duration
	KeepAliveDuration   *time.Duration
}
