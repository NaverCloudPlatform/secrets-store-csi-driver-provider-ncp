// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	credentials "github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/credentials"
	hmac "github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/hmac"
)

// mustURL parses a URL the test itself built. The provider constructors take a
// parsed URL because cmd/main.go validates it before the server starts.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// assertSignedRequest fails the test unless the request carries the NCP auth headers
// AND the signature matches the actual method/path/query (recomputed with the test key).
func assertSignedRequest(t *testing.T, r *http.Request) {
	t.Helper()
	ts := r.Header.Get("x-ncp-apigw-timestamp")
	ak := r.Header.Get("x-ncp-iam-access-key")
	sig := r.Header.Get("x-ncp-apigw-signature-v2")
	if ts == "" || ak == "" || sig == "" {
		t.Errorf("missing auth headers on %s", r.URL.RequestURI())
		return
	}
	want := hmac.Sign("sk", r.Method, r.URL.RequestURI(), ak, ts)
	if sig != want {
		t.Errorf("signature mismatch on %s: got %q want %q", r.URL.RequestURI(), sig, want)
	}
}

// Verifies name->id paging lookup, value fetch, secretKey extraction, not-found,
// and that every request carries the signed auth headers.
func TestGetSecretContent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		assertSignedRequest(t, r)
		if r.URL.Query().Get("pageNo") == "1" { // page 1: no match, more pages
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"currentPageNo": 1, "totalPageNo": 2,
				"secretList": []map[string]string{{"secretId": "x", "secretName": "other"}},
			}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{ // page 2: match
			"currentPageNo": 2, "totalPageNo": 2,
			"secretList": []map[string]string{{"secretId": "sid-42", "secretName": "my-secret"}},
		}})
	})
	mux.HandleFunc("/secrets/sid-42/values", func(w http.ResponseWriter, r *http.Request) {
		assertSignedRequest(t, r)
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"decryptedSecretChain": map[string]string{"active": `{"id":"alice","password":"pw"}`},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))

	got, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "my-secret"})
	if err != nil || got != `{"id":"alice","password":"pw"}` {
		t.Fatalf("full value: got %q, err %v", got, err)
	}

	got, err = p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "my-secret", SecretKey: "id"})
	if err != nil || got != "alice" {
		t.Fatalf("secretKey extract: got %q, err %v", got, err)
	}

	if _, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "missing"}); err == nil {
		t.Fatal("expected error for missing secret")
	}
}

// A 200 response without a data field must error with a message naming the
// missing data, not be misread as an empty page and blamed on the secret name.
func TestGetSecretContent_MalformedList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`)) // 200 OK, but no data
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	_, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"})
	if err == nil {
		t.Fatal("expected error for secret list response missing data")
	}
	if !strings.Contains(err.Error(), "missing data") {
		t.Fatalf("expected error to mention missing data, got %v", err)
	}
}

// A 200 response without decryptedSecretChain must error, not mount an empty value.
func TestGetSecretContent_MalformedValues(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1,
			"secretList": []map[string]string{{"secretId": "sid", "secretName": "s"}},
		}})
	})
	mux.HandleFunc("/secrets/sid/values", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`)) // 200 OK, but no data/decryptedSecretChain
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	if _, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"}); err == nil {
		t.Fatal("expected error for values response missing decryptedSecretChain")
	}
}

// rotatingSource hands out a different access key on every call, so the test
// can tell whether get() resolves credentials per request or caches them.
type rotatingSource struct {
	mu sync.Mutex
	n  int
}

func (s *rotatingSource) Credentials(context.Context) (credentials.Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return credentials.Value{AccessKey: fmt.Sprintf("ak%d", s.n), SecretKey: "sk"}, nil
}

func TestGetSecretContent_ResolvesCredentialsPerRequest(t *testing.T) {
	// Handlers run on their own goroutines, so guard the recorder.
	var mu sync.Mutex
	var seen []string
	record := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r.Header.Get("x-ncp-iam-access-key"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1,
			"secretList": []map[string]string{{"secretId": "sid", "secretName": "s"}},
		}})
	})
	mux.HandleFunc("/secrets/sid/values", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"decryptedSecretChain": map[string]string{"active": "v"},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProviderWithCredentials(mustURL(t, srv.URL), &rotatingSource{})
	if _, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"}); err != nil {
		t.Fatal(err)
	}

	// One lookup call and one values call, each with freshly resolved keys.
	if len(seen) != 2 || seen[0] != "ak1" || seen[1] != "ak2" {
		t.Fatalf("expected per-request credential resolution, got %v", seen)
	}
}

// Non-string values must be mounted as their original JSON text. Decoding into
// interface{} sent every number through float64, so 0.75 mounted as "1" and
// integers past 2^53 came out altered, silently and without an error.
func TestExtractJSONValue(t *testing.T) {
	const doc = `{"name":"alice","ratio":0.75,"big":12345678901234567890,` +
		`"port":8080,"on":true,"obj":{"b":1,"a":2},"arr":[1,2],"none":null}`

	for _, tc := range []struct{ key, want string }{
		{"name", "alice"},
		{"ratio", "0.75"},
		{"big", "12345678901234567890"},
		{"port", "8080"},
		{"on", "true"},
		{"obj", `{"b":1,"a":2}`}, // key order preserved, not re-encoded
		{"arr", "[1,2]"},
		{"none", "null"},
	} {
		got, err := extractJSONValue(doc, tc.key)
		if err != nil || got != tc.want {
			t.Errorf("key %q: got %q (err %v), want %q", tc.key, got, err, tc.want)
		}
	}

	if _, err := extractJSONValue(doc, "absent"); err == nil {
		t.Error("expected error for a key that is not in the secret")
	}
}

// When a secret is not a JSON object the decoder stops on one of its bytes and
// names it, and this error travels to the provider log and the pod's events.
// The value is the secret, so neither the text nor the byte may appear.
func TestExtractJSONValue_ErrorDoesNotQuoteTheSecret(t *testing.T) {
	for _, secret := range []string{"hunter2", "{bad", "-----BEGIN RSA PRIVATE KEY-----", "[1,2]", "null"} {
		_, err := extractJSONValue(secret, "name")
		if err == nil {
			t.Fatalf("expected %q to be rejected", secret)
		}
		// Exact equality rather than a search for the secret: the decoder names
		// whichever byte it stopped on, which is not always the first -- "{bad"
		// stops on 'b' -- and looking for the byte at all ties this to how the
		// standard library words the error. One known message cannot carry any
		// of them.
		if got := err.Error(); got != "secret is not a JSON object" {
			t.Errorf("error may only be the fixed message, got %q", got)
		}
	}
}

// The id comes back from the API and goes straight into a path. Without
// escaping, one carrying a slash or a query marker would change which resource
// is addressed -- and the signature covers whatever URL is built, so the
// request would be signed for the wrong thing rather than rejected.
func TestGetSecretContent_EscapesSecretID(t *testing.T) {
	const id = "a/b?c#d"
	var valuesPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1,
			"secretList": []map[string]string{{"secretId": id, "secretName": "s"}},
		}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		valuesPath = r.URL.EscapedPath()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"decryptedSecretChain": map[string]string{"active": "v"},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	if _, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"}); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if want := "/secrets/" + url.PathEscape(id) + "/values"; valuesPath != want {
		t.Errorf("values path = %q, want %q", valuesPath, want)
	}
}

// A server that reports the same currentPageNo no matter which page was asked
// for must not spin the lookup forever: the loop ends on the client's own
// counter. The mock in TestGetSecretContent honors pageNo, so it cannot catch
// this on its own.
func TestFindSecretIdByName_ServerIgnoresPageNo(t *testing.T) {
	var mu sync.Mutex
	calls := 0

	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()

		// Escape hatch so a regression fails this test instead of hanging it.
		if n > 4 {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"currentPageNo": 99, "totalPageNo": 2, "secretList": []map[string]string{},
			}})
			return
		}
		// currentPageNo is pinned to 1 whatever pageNo was requested.
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 2,
			"secretList": []map[string]string{{"secretId": "x", "secretName": "other"}},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	if _, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "my-secret"}); err == nil {
		t.Fatal("expected a not-found error")
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected exactly 2 page requests for totalPageNo=2, got %d", calls)
	}
}

// A response that keeps claiming more pages must stop at the cap instead of
// paging forever.
func TestFindSecretIdByName_PageCap(t *testing.T) {
	var mu sync.Mutex
	calls := 0

	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1 << 20,
			"secretList": []map[string]string{{"secretId": "x", "secretName": "other"}},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	_, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "my-secret"})
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected the page cap to stop the lookup, got %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != maxSecretListPages {
		t.Fatalf("expected %d page requests, got %d", maxSecretListPages, calls)
	}
}

// Endpoints differ in path as well as host: KR isolated-key and JPN sit under
// /secretmanager/api/v1 while the KR global-key endpoint uses /api/v1. The base
// path has to reach both the request URL and the signature.
func TestGetSecretContent_EndpointBasePath(t *testing.T) {
	for _, basePath := range []string{"/secretmanager/api/v1", "/api/v1", ""} {
		t.Run("basePath="+basePath, func(t *testing.T) {
			var mu sync.Mutex
			var paths []string

			mux := http.NewServeMux()
			mux.HandleFunc(basePath+"/secrets", func(w http.ResponseWriter, r *http.Request) {
				assertSignedRequest(t, r)
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
					"currentPageNo": 1, "totalPageNo": 1,
					"secretList": []map[string]string{{"secretId": "sid", "secretName": "s"}},
				}})
			})
			mux.HandleFunc(basePath+"/secrets/sid/values", func(w http.ResponseWriter, r *http.Request) {
				assertSignedRequest(t, r)
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
					"decryptedSecretChain": map[string]string{"active": "v"},
				}})
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL+basePath))
			got, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"})
			if err != nil || got != "v" {
				t.Fatalf("got %q, err %v", got, err)
			}

			mu.Lock()
			defer mu.Unlock()
			want := []string{basePath + "/secrets", basePath + "/secrets/sid/values"}
			if len(paths) != 2 || paths[0] != want[0] || paths[1] != want[1] {
				t.Fatalf("requested %v, want %v", paths, want)
			}
		})
	}
}

// A failed call must carry what the API said. Without it a bad key, a missing
// Sub Account policy and a clock skew are indistinguishable in the logs.
func TestGetSecretContent_ErrorBodyIsReported(t *testing.T) {
	const apiErr = `{"error":{"errorCode":"210","message":"Authentication Failed"}}`

	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(apiErr))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	_, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Authentication Failed") {
		t.Fatalf("error should carry the status and the API message, got: %v", err)
	}
}

// A 200 body is the secret itself, so a decode failure must not quote the byte
// it stopped on -- the same rule extractJSONValue follows, applied one layer up
// where the body has not been read yet.
func TestGetSecretContent_DecodeErrorDoesNotQuoteTheBody(t *testing.T) {
	const secret = "s3cret-value"

	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(secret))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	_, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"})
	if err == nil {
		t.Fatal("expected an error")
	}
	// Exact equality rather than a search for the planted value: the decoder
	// names whichever byte it stopped on, which is one character, and a search
	// for one character finds it in any English word. One known message cannot
	// carry any of them.
	if got, want := err.Error(), "failed to get secret[s]: response is not valid JSON"; got != want {
		t.Fatalf("error may only be the fixed message, got %q", got)
	}
}

// An oversized response must not be read without bound.
func TestGetSecretContent_ResponseSizeIsBounded(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"currentPageNo":1,"totalPageNo":1,"secretList":[{"secretId":"sid","secretName":"s"},`))
		// Never terminates the JSON: without a cap the decoder reads forever.
		chunk := strings.Repeat(`{"secretId":"x","secretName":"y"},`, 1024)
		for written := 0; written < maxResponseBytes+(1<<20); written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	_, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"})
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("a response cut at the cap should say so, got: %v", err)
	}
}

// The decoder reads from the connection, so a body that stops early fails the
// decode too. That is the network, not the API sending something malformed,
// and it quotes nothing of the body, so it must not read as "not valid JSON".
func TestGetSecretContent_CutOffBodyIsNotReportedAsInvalidJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte(`{"data":{"currentPageNo":1,`))
		// Returning short of Content-Length makes the server close the
		// connection, which the client reads as an unexpected EOF.
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	_, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"})
	if err == nil || strings.Contains(err.Error(), "not valid JSON") || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("a cut-off body should report the read failure, got: %v", err)
	}
}

// A type mismatch quotes the body as much as a syntax error can, so it gets
// the same fixed message.
func TestGetSecretContent_TypeErrorDoesNotQuoteTheBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":"s3cret-value"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	_, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"})
	if got, want := fmt.Sprint(err), "failed to get secret[s]: response is not valid JSON"; got != want {
		t.Fatalf("error may only be the fixed message, got %q", got)
	}
}

// A name or key that matches nothing is quoted back, and nothing but the
// document size bounds either.
func TestGetSecretContent_QuotedNamesAreClipped(t *testing.T) {
	long := strings.Repeat("x", 64<<10)
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1,
			"secretList": []map[string]string{{"secretId": "sid", "secretName": "s"}},
		}})
	})
	mux.HandleFunc("/secrets/sid/values", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"decryptedSecretChain": map[string]string{"active": `{"k":"v"}`},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	for _, op := range []ObjectParam{{ObjectName: long}, {ObjectName: "s", SecretKey: long}} {
		_, err := p.GetSecretContent(context.Background(), op)
		if err == nil {
			t.Fatal("expected an error")
		}
		if n := len(err.Error()); n > 1<<10 {
			t.Fatalf("error is %d bytes, want it clipped", n)
		}
	}
}

// decryptedSecretChain can arrive without an active value. Decoding that into a
// plain string yielded "" and mounted an empty file with no error at all.
func TestGetSecretContent_MissingActiveValue(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1,
			"secretList": []map[string]string{{"secretId": "sid", "secretName": "s"}},
		}})
	})
	mux.HandleFunc("/secrets/sid/values", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"decryptedSecretChain":{}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	got, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"})
	if err == nil {
		t.Fatalf("expected an error, got value %q mounted instead", got)
	}
}

// An empty ACTIVE value is a real value and must still be served.
func TestGetSecretContent_EmptyActiveValue(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1,
			"secretList": []map[string]string{{"secretId": "sid", "secretName": "s"}},
		}})
	})
	mux.HandleFunc("/secrets/sid/values", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"decryptedSecretChain":{"active":""}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	got, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"})
	if err != nil || got != "" {
		t.Fatalf("got %q, err %v; want an empty value and no error", got, err)
	}
}

// Following a redirect would resend the signed headers to a URI the signature
// does not cover, at a host nothing validated.
func TestGetSecretContent_RedirectNotFollowed(t *testing.T) {
	var mu sync.Mutex
	var elsewhereHit bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		elsewhereHit = true
		mu.Unlock()
		if r.Header.Get("x-ncp-iam-access-key") != "" {
			t.Error("signed headers were forwarded across a redirect")
		}
	}))
	defer elsewhere.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/secrets", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	if _, err := p.GetSecretContent(context.Background(), ObjectParam{ObjectName: "s"}); err == nil {
		t.Fatal("expected the redirect to fail the request")
	}
	mu.Lock()
	defer mu.Unlock()
	if elsewhereHit {
		t.Error("the redirect target was contacted")
	}
}

// A canceled mount has to stop calling the API. Without the context reaching
// the HTTP layer the provider ran every request to completion and answered a
// caller that had already gone away.
func TestGetSecretContent_ContextCanceled(t *testing.T) {
	var mu sync.Mutex
	var hits int

	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1,
			"secretList": []map[string]string{{"secretId": "sid", "secretName": "s"}},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := NewSecretManagerProvider("ak", "sk", mustURL(t, srv.URL))
	_, err := p.GetSecretContent(ctx, ObjectParam{ObjectName: "s"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the cancellation to surface, got %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("made %d API calls after the context was canceled", hits)
	}
}
