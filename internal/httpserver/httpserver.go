package httpserver

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"

	//
	"bifrost/api"
	"bifrost/internal/globals"
	"bifrost/internal/signature"
)

const (
	statusServiceUnavailableBody = "Service Unavailable"
)

type HttpServer struct {
	*http.Server
}

// TODO
func NewHttpServer() (server *HttpServer) {

	server = &HttpServer{
		&http.Server{
			ReadTimeout:  *globals.Application.Config.Listener.Options.ReadTimeoutDuration,
			WriteTimeout: *globals.Application.Config.Listener.Options.WriteTimeoutDuration,
		},
	}

	return server
}

// getRequestAuthBucketCredential returns the bucket credential associated with the request
// TODO: Refactor to transform into a map[string]func(*http.Request) (*api.BucketCredentialT, error)
func getRequestAuthBucketCredential(request *http.Request) (*api.BucketCredentialT, error) {

	switch globals.Application.Config.Authentication.ClientCredentials.Type {
	case "none":

		if reflect.ValueOf(globals.Application.Config.Authentication.ClientCredentials.None).IsZero() {
			return nil, fmt.Errorf("client credentials not defined for type: 'none'")
		}

		//
		for _, credentialObj := range globals.Application.Config.Authentication.BucketCredentials {

			if credentialObj.Name == globals.Application.Config.Authentication.ClientCredentials.None.BucketCredentialRef.Name {
				return &credentialObj, nil
			}
		}

	case "s3":

		invalidAuthHeaderMessage := "invalid authorization header"

		authHeader := request.Header.Get("Authorization")
		if authHeader == "" {
			return nil, fmt.Errorf("authorization header not found")
		}

		authHeaderParts := strings.Split(authHeader, " ")
		if len(authHeaderParts) != 2 {
			return nil, fmt.Errorf(invalidAuthHeaderMessage)
		}

		if strings.ToUpper(authHeaderParts[0]) != "AWS4-HMAC-SHA256" {
			return nil, fmt.Errorf(invalidAuthHeaderMessage)
		}

		authHeaderParams := strings.Split(authHeaderParts[1], ",")
		for _, paramObj := range authHeaderParams {
			partParts := strings.Split(paramObj, "=")
			if len(partParts) != 2 {
				return nil, fmt.Errorf(invalidAuthHeaderMessage)
			}

			if strings.ToUpper(partParts[0]) == "CREDENTIAL" {

				credentialParts := strings.Split(partParts[1], "/")
				if len(credentialParts) != 5 {
					return nil, fmt.Errorf(invalidAuthHeaderMessage)
				}

				accessKeyId := credentialParts[0]
				for _, credentialObj := range globals.Application.Config.Authentication.BucketCredentials {

					if credentialObj.AccessKeyId == accessKeyId {
						return &credentialObj, nil
					}
				}
			}
		}
	}

	//
	return nil, fmt.Errorf("unable to find bucket credential")
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

	// Get a proper bucket credential for the current request
	bucketCredential, err := getRequestAuthBucketCredential(request)
	if err != nil {
		err = fmt.Errorf("failed to select a bucket credential from request data: %s", err.Error())
		return
	}

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
		}
	}

	// Sign the request
	err = signature.SignS3Version4(targetReq, bucketCredential.AwsConfig)
	if err != nil {
		err = fmt.Errorf("failed to sign request: %s", err.Error())
		return
	}

	//
	globals.Application.Logger.Infof(
		"delivered request {requestId: '%s', host: '%s', path: '%s', query: %s, headers '%v'}",
		requestId,
		targetReq.Host,
		targetReq.URL.Path,
		targetReq.URL.RawQuery,
		targetReq.Header,
	)

	//
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

	// TODO: Configure and use the server previously crafted
	err := http.ListenAndServe(httpAddr, mux)
	if err != nil {
		globals.Application.Logger.Errorf("Server failed. Reason: %s", err.Error())
	}
}

func (s *HttpServer) Stop() {
	globals.Application.Logger.Infof("HTTP server stopped: %v", s.Close())
}
