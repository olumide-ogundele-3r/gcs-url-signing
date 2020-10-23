package main

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
)

const (
	maximumExpiration = 604800
)

func generateSignedURL(serviceAccount, bucketName, resourcePath, httpMethod  string, expiration int, queryParameters,
	headers map[string]string) (string, error) {
	// maximum expiry date is 7 days (604800)
	if expiration > maximumExpiration {
		return "", fmt.Errorf("expiration: time can't be longer than %d seconds (7 days)", maximumExpiration)
	}

	// Construct the canonical request:
	encodedURI := url.QueryEscape(strings.TrimLeft(resourcePath, "/"))
	canonicalURI := fmt.Sprintf("/%s", encodedURI)
	currentTime := time.Now().UTC()
	requestTimestamp := currentTime.Format(time.RFC3339)
	year, month, day := currentTime.Date()
	datestamp := fmt.Sprintf("%d%d%d", year, month, day)

	jsonKey, err := ioutil.ReadFile(serviceAccount)
	if err != nil {
		return "", fmt.Errorf("ioutil.ReadFile: %v", err)
	}

	googleCredentials, err := google.JWTConfigFromJSON(jsonKey)
	if err != nil {
		return "", fmt.Errorf("google.JWTConfigFromJSON: %v", err)
	}

	email := googleCredentials.Email
	scope := fmt.Sprintf("%s/auto/storage/goog4_request", datestamp)
	credential :=  fmt.Sprintf("%s/%s", email, scope)

	host :=  fmt.Sprintf("%s.storage.googleapis.com", bucketName)
	headers["host"] = host

	// Construct canonical headers
	var headerKeys []string

	for key := range headers {
		headerKeys = append(headerKeys, key)
	}

	// Sort all headers by header name using a lexicographical sort by code point value.
	sort.Strings(headerKeys)

	var canonicalHeaders strings.Builder
	var headerString strings.Builder

	for _, key := range headerKeys {
		value := headers[key]
		canonicalHeaders.WriteString(strings.ToLower(fmt.Sprintf("%s:%s\n", key, value)))
		headerString.WriteString(strings.ToLower(fmt.Sprintf("%s;", key)))
	}

	signedHeaders := headerString.String()
	signedHeaders = signedHeaders[:len(signedHeaders) - 1] // remove the trailing ";"
	fmt.Println("header: ", canonicalHeaders.String())
	fmt.Println("signed-header: ", signedHeaders) // remove the trailing ";"

	// Canonical Query string
	var parameterKeys []string

	queryParameters["X-Goog-Algorithm"] = "GOOG4-RSA-SHA256"
	queryParameters["X-Goog-Credential"] = credential
	queryParameters["X-Goog-Date"] = requestTimestamp
	queryParameters["X-Goog-Expires"] = strconv.Itoa(expiration)
	queryParameters["X-Goog-SignedHeaders"] = signedHeaders

	for key := range queryParameters {
		parameterKeys = append(parameterKeys, key)
	}

	// Sort all parameter by parameter name using a lexicographical sort by code point value.
	sort.Strings(parameterKeys)

	var queryString strings.Builder

	for _, key := range parameterKeys {
		value := queryParameters[key]
		queryString.WriteString(fmt.Sprintf("%s=%s&", key, value))
	}

	q := queryString.String()
	canonicalQueryString := q[:len(q) - 1]  // remove the trailing "&"

	// HTTP_VERB
	// PATH_TO_RESOURCE
	// CANONICAL_QUERY_STRING
	// CANONICAL_HEADERS
	//
	// SIGNED_HEADERS
	// PAYLOAD

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", httpMethod, canonicalURI, canonicalQueryString,
		canonicalHeaders, signedHeaders, "UNSIGNED-PAYLOAD")

	// Construct the string-to-sign


	return "", nil
}