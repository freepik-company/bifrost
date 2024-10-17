package signature

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Sign a S3 request using AWS Signature Version 4.
// Ref:
func SignS3Version4(cfg *aws.Config, req *http.Request, requestBody *[]byte) (err error) {

	awsCredentials, err := cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		log.Fatalf("unable to get credentials, %v", err)
	}

	//
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if len(*requestBody) > 0 {
		payloadHash = fmt.Sprintf("%x", sha256.Sum256(*requestBody))
	}

	req.Header.Set("x-amz-content-sha256", payloadHash)

	// Restore the content-length to the original value
	req.ContentLength = int64(len(*requestBody))

	// Trust the X-Amz-Date header if it is present in the request
	signingTime := time.Now()
	dateHeader := req.Header.Get("x-amz-date")
	if dateHeader != "" {

		signingTime, err = time.Parse("20060102T150405Z", dateHeader)
		if err != nil {
			return fmt.Errorf("invalid X-Amz-Date header format: %v", err)
		}
	}

	// Create a new signer for the version 4 (S3 uses version 4 of the signatures)
	signer := v4.NewSigner()

	// Generate the signature for the request using the loaded credentials
	err = signer.SignHTTP(context.TODO(), awsCredentials, req, payloadHash, "s3", cfg.Region, signingTime)
	if err != nil {
		return fmt.Errorf("error signing request: %s", err.Error())
	}

	return nil
}

// Sign a S3 request using AWS Signature Version 2.
// Ref: https://github.com/jouve/haproxy-s3-gateway/blob/main/haproxy/aws_signature.lua
func SignS3Version2(req *http.Request, cfg *aws.Config) error {

	awsCredentials, err := cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("unable to get credentials, %v", err)
	}

	// Obtener la fecha actual en el formato HTTP.
	date := time.Now().UTC().Format(http.TimeFormat)

	// Establecer los encabezados "Host" y "Date".
	req.Header.Set("Host", req.Host)
	req.Header.Set("Date", date)

	// Crear la cadena para firmar.
	stringToSign := strings.Join([]string{
		req.Method,
		"",
		"",
		date,
		req.URL.Path,
	}, "\n")

	// Craft HMAC-SHA1 hash
	h := hmac.New(sha1.New, []byte(awsCredentials.SecretAccessKey))
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Set "Authorization" header
	authHeader := fmt.Sprintf("AWS %s:%s", awsCredentials.AccessKeyID, signature)
	req.Header.Set("Authorization", authHeader)

	return nil
}
