package signature

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Sign a S3 request using AWS Signature Version 4.
// Ref:
func SignS3Version4(cfg *aws.Config, req *http.Request, payloadHash string) (err error) {

	awsCredentials, err := cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		log.Fatalf("unable to get credentials, %v", err)
	}

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
