package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

const Algorithm = "AWS4-HMAC-SHA256"

func main() {
	fmt.Println(formatTime(time.Now()))
	authorization := `GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08 HTTP/1.1
Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7
content-type: application/x-www-form-urlencoded; charset=utf-8
host: iam.amazonaws.com
x-amz-date: 20150830T123600Z`
	_ = authorization

	// https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
	// Task 1: Create a canonical request for Signature Version 4

	headers := map[string][]string{
		"content-type": []string{"application/x-www-form-urlencoded; charset=utf-8"},
		"host":         []string{"iam.amazonaws.com"},
		"x-amz-date":   []string{"20150830T123600Z"},
	}

	canonicalRequest := createCanonicalRequest(
		"GET",
		"/",
		"Action=ListUsers&Version=2010-05-08",
		headers,
		[]byte(""),
	)
	fmt.Printf("canonical request: %s\n\n", canonicalRequest)
	fmt.Printf("hash of canonical request: %s\n\n", hash([]byte(canonicalRequest)))

	// Task 2: Create a string to sign for Signature Version 4
	var (
		requestDate     = time.Date(2015, 8, 30, 12, 36, 0, 0, time.Local)
		credentialScope = "20150830/us-east-1/iam/aws4_request"
		stringToSign    = createStringToSign(requestDate, credentialScope, hash([]byte(canonicalRequest)))
	)
	fmt.Printf("string to sign: %s\n\n", stringToSign)

	// Task 3: Calculate the signature for AWS Signature Version 4
	var (
		secretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		region          = "us-east-1"
		service         = "iam"
	)
	signingKey := createSigningKey(secretAccessKey, requestDate, region, service)
	fmt.Printf("signingKey: %s\n\n", signingKey)

	signingKeyBytes, err := hex.DecodeString(signingKey)
	if err != nil {
		log.Fatal(err)
	}
	signature := hex.EncodeToString(HMAC(signingKeyBytes, []byte(stringToSign)))
	fmt.Printf("signature: %s\n\n", signature)

	var (
		accessKeyId   = "AKIDEXAMPLE"
		signedHeaders = createSignedHeader(headers)
	)
	header := buildHeader(accessKeyId, credentialScope, signedHeaders, signature)
	fmt.Printf("header: %s\n", header)
}

func createCanonicalHeader(headers map[string][]string) string {
	var header []string
	for k, v := range headers {
		h := strings.Join([]string{
			strings.TrimSpace(strings.ToLower(k)),
			strings.TrimSpace(strings.Join(v, " ")),
		}, ":")
		header = append(header, h)
	}
	sort.Strings(header)
	return strings.Join(header, "\n") + "\n"
}

func hash(msg []byte) string {
	h := sha256.New()
	h.Write(msg)
	return strings.ToLower(hex.EncodeToString(h.Sum(nil)))
}

func createSignedHeader(headers map[string][]string) string {
	var header []string
	for k := range headers {
		header = append(header, strings.ToLower(strings.TrimSpace(k)))
	}
	sort.Strings(header)
	return strings.Join(header, ";")
}

func createCanonicalRequest(httpRequestMethod, canonicalURI, canonicalQueryString string, headers map[string][]string, body []byte) string {
	canonicalHeaders := createCanonicalHeader(headers)
	signedHeaders := createSignedHeader(headers)
	requestPayload := hash(body)

	return strings.Join([]string{
		httpRequestMethod,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		requestPayload,
	}, "\n")
}

func createStringToSign(requestDateTime time.Time, credentialScope, hashedCanonicalRequest string) string {
	return strings.Join([]string{
		Algorithm,
		formatTime(requestDateTime),
		credentialScope,
		hashedCanonicalRequest,
	}, "\n")
}

func formatTime(t time.Time) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(
			t.Format(time.RFC3339),
			"-", ""),
		":", "")
}

func createSigningKey(secretAccessKey string, date time.Time, region, service string) string {
	kSecret := secretAccessKey
	kDate := HMAC([]byte("AWS4"+kSecret), []byte(date.Format("20060102"))) // YYYYMMDD
	kRegion := HMAC(kDate, []byte(region))
	kService := HMAC(kRegion, []byte(service))
	kSigning := HMAC(kService, []byte("aws4_request"))
	return hex.EncodeToString(kSigning)
}

func HMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func buildHeader(accessKeyId, credentialScope, signedHeaders, signature string) string {
	return fmt.Sprintf(`Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s`, Algorithm, accessKeyId, credentialScope, signedHeaders, signature)
}
