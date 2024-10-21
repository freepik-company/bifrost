package httpserver

import (
	"crypto/tls"
	"encoding/xml"
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

	//
	"golang.org/x/net/netutil"
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

// TODO
func (s *HttpServer) SetAddr(addr string) {
	s.Server.Addr = addr
}

// TODO
func (s *HttpServer) SetHandler(handler http.Handler) {
	s.Server.Handler = handler
}

// getRequestAuthParam extracts a parameter from the Authorization header of the request
// The header value is expected to be in the format: <Auth type> <Param1=value1,Param2=value2>
func getRequestAuthParam(request *http.Request, param string) (string, error) {

	authHeader := request.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header not found")
	}

	//
	invalidAuthHeaderMessage := "invalid authorization header"

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) < 2 {
		return "", fmt.Errorf(invalidAuthHeaderMessage)
	}

	if strings.ToUpper(authHeaderParts[0]) != "AWS4-HMAC-SHA256" {
		return "", fmt.Errorf(invalidAuthHeaderMessage)
	}

	// Sanitize potential unwanted spaces
	authHeaderParamsStr := ""
	if len(authHeaderParts) >= 2 {
		for i, part := range authHeaderParts {
			if i == 0 {
				continue
			}

			authHeaderParamsStr += part
		}
	}

	// Split the auth header params
	authHeaderParams := strings.Split(authHeaderParamsStr, ",")
	for _, paramObj := range authHeaderParams {
		partParts := strings.Split(paramObj, "=")
		if len(partParts) != 2 {
			return "", fmt.Errorf(invalidAuthHeaderMessage)
		}

		if strings.EqualFold(strings.TrimSpace(partParts[0]), param) {
			return strings.TrimSpace(partParts[1]), nil
		}
	}

	//
	return "", nil
}

// getBucketCredential returns the bucket credential associated with the request
// TODO: Refactor to transform into a map[string]func(*http.Request) (*api.BucketCredentialT, error)
func getBucketCredential(request *http.Request) (*api.BucketCredentialT, error) {

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

		headerAuthCredentialParam, err := getRequestAuthParam(request, "credential")
		if err != nil {
			return nil, fmt.Errorf("failed to get credential from 'authorization' header: %s", err.Error())
		}

		credentialParts := strings.Split(headerAuthCredentialParam, "/")
		if len(credentialParts) != 5 {
			return nil, fmt.Errorf("invalid authorization header")
		}

		accessKeyId := credentialParts[0]
		for _, credentialObj := range globals.Application.Config.Authentication.BucketCredentials {

			if credentialObj.AccessKeyId == accessKeyId {
				return &credentialObj, nil
			}
		}
	}

	//
	return nil, fmt.Errorf("unable to find bucket credential")
}

// isValidSignature verifies the signature of the request using the provided bucket credential
// It produces another signature over the same request and compares them
func isValidSignature(bucketCredential *api.BucketCredentialT, request *http.Request) (bool, error) {

	globals.Application.Logger.Debugf("[signature validation] client original request: %v", request)

	// Craft a new request to be fake-signed
	simulatedReq, err := http.NewRequest(request.Method, request.URL.String(), nil)
	if err != nil {
		return false, fmt.Errorf("failed to create simulated request: %s", err.Error())
	}

	// Copy relevant data from original request
	simulatedReq.Host = request.Host
	simulatedReq.ContentLength = request.ContentLength
	simulatedReq.URL.RawQuery = request.URL.RawQuery

	// Copy only the signed headers from the original request
	originAuthSignedHeadersParam, err := getRequestAuthParam(request, "signedheaders")
	if err != nil {
		return false, fmt.Errorf("failed to get 'signedheaders' param from origin 'authorization' header: %s", err.Error())
	}

	requestSignedHeaders := strings.Split(originAuthSignedHeadersParam, ";")

	for _, signedHeader := range requestSignedHeaders {
		if strings.EqualFold(signedHeader, "host") {
			continue
		}

		simulatedReq.Header.Add(signedHeader, request.Header.Get(signedHeader))
	}

	globals.Application.Logger.Debugf("[signature validation] simulated request before signing: %v", simulatedReq)

	// Sign the faked request with provided credentials
	err = signature.SignS3Version4(bucketCredential.AwsConfig, simulatedReq)
	if err != nil {
		return false, fmt.Errorf("failed to sign simulated request: %s", err.Error())
	}

	globals.Application.Logger.Debugf("[signature validation] simulated request after signing: %v", simulatedReq)

	// Get both signatures and compare them
	originSignatureParam, err := getRequestAuthParam(request, "signature")
	if err != nil {
		return false, fmt.Errorf("failed to get 'signature' from origin 'authorization' header: %s", err.Error())
	}

	simulatedSignatureParam, err := getRequestAuthParam(simulatedReq, "signature")
	if err != nil {
		return false, fmt.Errorf("failed to get 'signature' from simulated 'authorization' header: %s", err.Error())
	}

	if originSignatureParam != simulatedSignatureParam {
		return false, nil
	}

	return true, nil
}

// TODO
// Ref: https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#ErrorCodeList
func (s *HttpServer) handleRequest(response http.ResponseWriter, request *http.Request) {

	var err, localErr error

	requestId := generateRandToken()

	//
	globals.Application.Logger.Infof(
		"received request {requestId: '%s', host: '%s', content-length: '%d', path: '%s', query: %s, headers '%v'}",
		requestId,
		request.Host,
		request.ContentLength,
		request.URL.Path,
		request.URL.RawQuery,
		request.Header,
	)

	defer func() {
		if err != nil {
			globals.Application.Logger.Errorf(
				"failed request {requestId: '%s'}: %s",
				requestId,
				err.Error(),
			)

			response.WriteHeader(http.StatusInternalServerError)
			response.Header().Set("Content-Type", "application/xml")

			errorResponse := &api.S3ErrorResponseT{
				Code:      "InternalError",
				Message:   err.Error(),
				Resource:  request.URL.Path,
				RequestId: requestId,
			}

			_, err := response.Write([]byte(xml.Header))
			if err != nil {
				globals.Application.Logger.Errorf("failed to write XML header: %s", err.Error())
				return
			}

			//
			encoder := xml.NewEncoder(response)
			err = encoder.Encode(errorResponse)
			if err != nil {
				globals.Application.Logger.Errorf("failed to XML encode error response: %s", err.Error())
			}

			// Optional: Flush the encoder to ensure all data is written
			encoder.Flush()
		}

	}()

	defer request.Body.Close()

	// Get a proper bucket credential for the current request
	bucketCredential, localErr := getBucketCredential(request)
	if localErr != nil {
		err = fmt.Errorf("failed to select a bucket credential from request data: %s", localErr.Error())
		return
	}

	// Verify the signature of the request when using S3 credentials for client authentication
	if globals.Application.Config.Authentication.ClientCredentials.Type == "s3" &&
		globals.Application.Config.Authentication.ClientCredentials.S3.SignatureVerification {

		isValid, localErr := isValidSignature(bucketCredential, request)
		if localErr != nil {
			err = fmt.Errorf("failed to validate request signature: %s", localErr.Error())
			return
		}

		if !isValid {
			err = fmt.Errorf("signature validation failed")
			return
		}
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

			DisableKeepAlives: globals.Application.Config.Target.Options.DisableKeepAlives,
		},
	}

	// Create a bare new request against the target
	// This is a clone of the original request with some params changed such as: the Host and the URL
	targetHostString := strings.Join([]string{globals.Application.Config.Target.Host, globals.Application.Config.Target.Port}, ":")

	targetRequestUrl := fmt.Sprintf("%s://%s%s",
		globals.Application.Config.Target.Scheme, targetHostString, request.URL.Path+"?"+request.URL.RawQuery)

	targetReq, localErr := http.NewRequest(request.Method, targetRequestUrl, request.Body)
	if localErr != nil {
		err = fmt.Errorf("failed to create request: %s", localErr.Error())
		return
	}
	defer targetReq.Body.Close()

	targetReq.Host = targetHostString
	targetReq.ContentLength = request.ContentLength
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
	localErr = signature.SignS3Version4(bucketCredential.AwsConfig, targetReq)
	if localErr != nil {
		err = fmt.Errorf("failed to sign request: %s", localErr.Error())
		return
	}

	//
	globals.Application.Logger.Infof(
		"delivered request {requestId: '%s', host: '%s', content-length: '%d', path: '%s', query: %s, headers '%v'}",
		requestId,
		targetReq.Host,
		targetReq.ContentLength,
		targetReq.URL.Path,
		targetReq.URL.RawQuery,
		targetReq.Header,
	)

	//
	targetResponse, localErr := targetClient.Do(targetReq)
	if localErr != nil {
		err = fmt.Errorf("failed to deliver request: %s", localErr.Error())
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
	_, localErr = io.Copy(response, targetResponse.Body)
	if localErr != nil {
		err = fmt.Errorf("failed copying body to the frontend: %s", localErr.Error())
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

	// Configure and use the server previously crafted
	s.SetAddr(httpAddr)
	s.SetHandler(mux)
	s.SetKeepAlivesEnabled(!globals.Application.Config.Listener.Options.DisableKeepAlives)

	//
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		globals.Application.Logger.Errorf("Server failed. Reason: %s", err.Error())
	}

	limitedListener := listener
	if globals.Application.Config.Listener.Options.MaxConcurrentConnections > 0 {
		limitedListener = netutil.LimitListener(listener, globals.Application.Config.Listener.Options.MaxConcurrentConnections)
	}

	err = s.Serve(limitedListener)
	if err != nil {
		globals.Application.Logger.Errorf("Server failed. Reason: %s", err.Error())
	}

}

func (s *HttpServer) Stop() {
	globals.Application.Logger.Infof("HTTP server stopped: %v", s.Close())
}
