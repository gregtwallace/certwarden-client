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

// httpClient is a custom http.Client that includes userAgent
type httpClient struct {
	http      *http.Client
	userAgent string
}

// newHttpClient creates a new httpClient
func newHttpClient() (client *httpClient) {
	// userAgent
	userAgent := fmt.Sprintf("LeGoCertHubClient/%s (%s; %s)", appVersion, runtime.GOOS, runtime.GOARCH)

	// create *Client
	client = &httpClient{
		http: &http.Client{
			// set client timeout
			Timeout:   30 * time.Second,
			Transport: http.DefaultTransport,
		},
		userAgent: userAgent,
	}

	return client
}

// getPemWithApiKey fetches a pem response from the LeGo server
func (c *httpClient) getPemWithApiKey(url, apiKey string) (pemContent []byte, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// set user agent
	req.Header.Set("User-Agent", c.userAgent)

	// set apiKey
	req.Header.Set("apiKey", apiKey)

	// do the request
	resp, err := c.http.Do(req)
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
