package signature

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Sign a S3 request using AWS Signature Version 4.
// Ref:
func SignS3Version4(req *http.Request, cfg *aws.Config) (err error) {

	awsCredentials, err := cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		log.Fatalf("unable to get credentials, %v", err)
	}

	//
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if req.Body != nil {
		requestPayload, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("error reading request body: %s", err.Error())
		}

		payloadHash = fmt.Sprintf("%x", sha256.Sum256(requestPayload))
		req.Body = io.NopCloser(bytes.NewReader(requestPayload))
	}

	req.Header.Set("x-amz-content-sha256", payloadHash)

	// Crear un nuevo firmador de la versión 4 (S3 utiliza la versión 4 de las firmas)
	signer := v4.NewSigner()

	// Generar la firma de la solicitud usando las credenciales cargadas
	err = signer.SignHTTP(context.TODO(), awsCredentials, req, payloadHash, "s3", cfg.Region, time.Now())
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
