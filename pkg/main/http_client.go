package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"
)

// httpCWRoundTripper implements RoundTrip with headers for CertWarden Client
type httpCWRoundTripper struct {
	userAgent string
}

func (rt *httpCWRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// always override user-agent
	req.Header.Set("User-Agent", rt.userAgent)

	return http.DefaultTransport.RoundTrip(req)
}

// makeHttpClient returns an http.Client with a custom transport to ensure certain headers
// are added to all requests
func makeHttpClient() (client *http.Client) {
	t := &httpCWRoundTripper{
		userAgent: fmt.Sprintf("CertWardenClient/%s (%s; %s)", appVersion, runtime.GOOS, runtime.GOARCH),
	}

	return &http.Client{
		// set client timeout
		Timeout:   30 * time.Second,
		Transport: t,
	}
}

// getPemWithApiKey fetches a pem response from the Cert Warden server
func (app *app) getPemWithApiKey(url, apiKey string) (pemContent []byte, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// set apiKey
	req.Header.Set("apiKey", apiKey)

	// do the request
	resp, err := app.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// read body (before err check to ensure body is always read completely)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// error if not code 200
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error fetching pem (status: %d)", resp.StatusCode)
	}

	// validate the response data is actually pem
	pemBlock, _ := pem.Decode(bodyBytes)
	if pemBlock == nil {
		return nil, errors.New("error fetching pem (data from server was not valid pem data)")
	}

	return bodyBytes, nil
}
