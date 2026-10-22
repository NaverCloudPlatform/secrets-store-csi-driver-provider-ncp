// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package hmac

import "testing"

// Fixed vector: base64(HMAC-SHA256("sk", "GET /api/v1/secrets?pageNo=1\n1700000000000\nak")).
// Signs only the request URI (path+query), not scheme/host.
func TestSign(t *testing.T) {
	got := Sign("sk", "GET", "/api/v1/secrets?pageNo=1", "ak", "1700000000000")
	const want = "WXRDq/UbheaXmRdghih+tAANrbfE7kawErkK7VkUGNo="
	if got != want {
		t.Fatalf("signature mismatch:\n got %q\nwant %q", got, want)
	}
}
