package api

import "encoding/xml"

type S3ErrorResponseT struct {
	XMLName xml.Name `xml:"Error"`

	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
	Resource  string `xml:"Resource"`
	RequestId string `xml:"RequestId"`
}
