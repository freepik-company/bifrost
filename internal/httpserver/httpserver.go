package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	//
	"bifrost/internal/globals"
	"bifrost/internal/signature"

	"github.com/aws/aws-sdk-go-v2/config"
)

const (
	statusServiceUnavailableBody = "Service Unavailable"
)

var (
// TargetHostString = strings.Join([]string{globals.Application.Config.Target.Host, globals.Application.Config.Target.Port}, ":")
)

type HttpServer struct {
	*http.Server
}

// TODO: Move this to the config package (or main)
func initConfig() {
	listenerReadTimeoutDuration, err := time.ParseDuration(globals.Application.Config.Listener.Options.ReadTimeout)
	if err != nil {
		log.Fatal("unable to parse listener read timeout duration")
	}

	globals.Application.Config.Listener.Options.ReadTimeoutDuration = &listenerReadTimeoutDuration

	// TODO
	listenerWriteTimeoutDuration, err := time.ParseDuration(globals.Application.Config.Listener.Options.WriteTimeout)
	if err != nil {
		log.Fatal("unable to parse listener write timeout duration")
	}

	globals.Application.Config.Listener.Options.WriteTimeoutDuration = &listenerWriteTimeoutDuration

	// TODO
	targetDialTimeoutDuration, err := time.ParseDuration(globals.Application.Config.Target.Options.DialTimeout)
	if err != nil {
		log.Fatal("unable to parse target dial timeout duration")
	}

	globals.Application.Config.Target.Options.DialTimeoutDuration = &targetDialTimeoutDuration

	// TODO
	targetKeepAliveDuration, err := time.ParseDuration(globals.Application.Config.Target.Options.KeepAlive)
	if err != nil {
		log.Fatal("unable to parse target keep-alive duration")
	}

	globals.Application.Config.Target.Options.KeepAliveDuration = &targetKeepAliveDuration

	// TODO
	for index, mod := range globals.Application.Config.Modifiers {
		// Compile regex for path modifiers
		if mod.Type == "path" {
			globals.Application.Config.Modifiers[index].Path.CompiledRegex = regexp.MustCompile(mod.Path.Pattern)
		}

		// Load AWS default config for signature modifiers
		if mod.Type == "signature" && mod.Signature.Type == "s3" {
			cfg, err := config.LoadDefaultConfig(context.TODO())
			if err != nil {
				log.Fatalf("unable to load SDK config, %v", err)
			}

			globals.Application.Config.Modifiers[index].Signature.AwsConfig = &cfg

			////////////// DEBUG

			awsCredentials, err := cfg.Credentials.Retrieve(context.TODO())
			if err != nil {
				log.Fatalf("unable to get credentials, %v", err)
			}

			log.Printf("region: %s # user: %s # pass: %s",
				globals.Application.Config.Modifiers[index].Signature.AwsConfig.Region,
				awsCredentials.AccessKeyID,
				awsCredentials.SecretAccessKey)
		}
	}
}

func generateRandToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// TODO
func NewHttpServer() (server *HttpServer) {

	initConfig()

	server = &HttpServer{
		&http.Server{
			ReadTimeout:  *globals.Application.Config.Listener.Options.ReadTimeoutDuration,
			WriteTimeout: *globals.Application.Config.Listener.Options.WriteTimeoutDuration,
		},
	}

	return server
}

func (s *HttpServer) handleRequest(response http.ResponseWriter, request *http.Request) {

	requestId := generateRandToken()

	//
	globals.Application.Logger.Infof(
		"received request {requestId: '%s', host: '%s', path: '%s', query: %s, headers '%v'}",
		requestId,
		request.Host,
		request.URL.Path,
		request.URL.RawQuery,
		request.Header,
	)

	var err error
	defer func() {
		if err != nil {
			globals.Application.Logger.Errorf(
				"failed request {requestId: '%s'}: %s",
				requestId,
				err.Error(),
			)

			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = response.Write([]byte(statusServiceUnavailableBody))
		}
	}()

	// TODO: Implement authentication as expressed in the config
	//result, err := handleAuthentication(request)

	// Generate a new client per request.
	// This decreases the performance but remove the possibility of issues caused by reusing the client
	targetClient := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   *globals.Application.Config.Target.Options.DialTimeoutDuration,
				KeepAlive: *globals.Application.Config.Target.Options.KeepAliveDuration,
			}).DialContext,

			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: globals.Application.Config.Target.Tls.SkipVerify,
			},
		},
	}

	// Create a bare new request against the target
	// This is a clone of the original request with some params changed such as: the Host and the URL
	targetHostString := strings.Join([]string{globals.Application.Config.Target.Host, globals.Application.Config.Target.Port}, ":")
	targetRequestUrl := fmt.Sprintf("%s://%s%s",
		globals.Application.Config.Target.Scheme, targetHostString, request.URL.Path+"?"+request.URL.RawQuery)

	targetReq, err := http.NewRequest(request.Method, targetRequestUrl, request.Body)
	if err != nil {
		err = fmt.Errorf("failed to create request: %s", err.Error())
		return
	}
	targetReq.Host = targetHostString
	targetReq.Header = request.Header

	// Apply the modifiers to the request before sending it (order matters)
	for _, modifier := range globals.Application.Config.Modifiers {
		switch modifier.Type {
		case "path":
			targetReq.URL.Path = modifier.Path.CompiledRegex.ReplaceAllString(targetReq.URL.Path, modifier.Path.Replace)

		case "header":
			// TODO

		case "signature":

			if modifier.Signature.Type == "s3" && modifier.Signature.Version == "v4" {
				signature.SignS3Version4(targetReq, modifier.Signature.AwsConfig)
			}

			if modifier.Signature.Type == "s3" && modifier.Signature.Version == "v2" {
				signature.SignS3Version2(targetReq, modifier.Signature.AwsConfig)
			}
		}
	}

	globals.Application.Logger.Infof(
		"delivered request {requestId: '%s', host: '%s', path: '%s', query: %s, headers '%v'}",
		requestId,
		targetReq.Host,
		targetReq.URL.Path,
		targetReq.URL.RawQuery,
		targetReq.Header,
	)

	// TODO
	targetResponse, err := targetClient.Do(targetReq)
	if err != nil {
		err = fmt.Errorf("failed to deliver request: %s", err.Error())
		return
	}

	// Clone the headers
	for k, v := range targetResponse.Header {
		for _, headV := range v {
			response.Header().Set(k, headV)
		}
	}

	// Clone status code in the response
	response.WriteHeader(targetResponse.StatusCode)

	// Clone the data without trully reading it
	_, err = io.Copy(response, targetResponse.Body)
	if err != nil {
		err = fmt.Errorf("failed copying body to the frontend: %s", err.Error())
		return
	}

	err = nil
}

func (s *HttpServer) Run(httpAddr string) {
	defer func() {
		globals.Application.Logger.Infof("Stopped HTTP server")
	}()

	// Create the webserver to serve the requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	globals.Application.Logger.Infof("Starting HTTP server on %s", httpAddr)

	err := http.ListenAndServe(httpAddr, mux)
	if err != nil {
		globals.Application.Logger.Errorf("Server failed. Reason: %s", err.Error())
	}
}

func (s *HttpServer) Stop() {
	globals.Application.Logger.Infof("HTTP server stopped: %v", s.Close())
}
