// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// Sign returns an NCP API Gateway v2 signature:
// base64(HMAC-SHA256(secretKey, "METHOD requestURI\ntimestamp\naccessKey")).
// requestURI is the path and query exactly as they will be sent, e.g.
// "/secretmanager/api/v1/secrets?pageNo=1".
func Sign(secretKey, method, requestURI, accessKey, timestamp string) string {
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(method + " " + requestURI + "\n" + timestamp + "\n" + accessKey))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
