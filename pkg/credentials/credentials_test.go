// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package credentials

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeCredentialFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "configure")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileProvider_Retrieve(t *testing.T) {
	path := writeCredentialFile(t, "ncloud_access_key_id = ak\nncloud_secret_access_key = sk\nsecretmanager_api_url = https://example.com/api/v1\n")

	v, err := NewFileProvider(path).Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if v.AccessKey != "ak" || v.SecretKey != "sk" {
		t.Fatalf("got %+v", v)
	}
	// File credentials never expire; a non-zero Expiration would make the
	// chain refresh them forever.
	if !v.Expiration.IsZero() {
		t.Fatalf("expected zero Expiration, got %v", v.Expiration)
	}
}

func TestFileProvider_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	_, err := NewFileProvider(path).Retrieve(context.Background())
	if err == nil {
		t.Fatal("expected error for a missing credential file")
	}
	// A file that was never mounted is the normal state under the server role,
	// and this error is read next to that provider's own. It has to stay
	// distinguishable from a file that is present and malformed.
	if want := fmt.Sprintf("credential file %s does not exist", path); err.Error() != want {
		t.Errorf("got %q, want %q", err, want)
	}
}

func TestFileProvider_MissingSecretKey(t *testing.T) {
	path := writeCredentialFile(t, "ncloud_access_key_id = ak\n")
	if _, err := NewFileProvider(path).Retrieve(context.Background()); err == nil {
		t.Fatal("expected error when the secret key is missing")
	}
}

// go-ini quotes the line it stopped on, and in this file that line is most
// likely the one holding the secret key. The error travels to the provider log,
// which is what an operator reads when both sources fail and the pod
// crash-loops -- the moment the file is most likely to be malformed.
func TestFileProvider_ErrorDoesNotQuoteTheFile(t *testing.T) {
	const secret = "s3cret-value"
	for _, content := range []string{
		// No delimiter: go-ini echoes the whole line.
		"ncloud_access_key_id = ak\nncloud_secret_access_key " + secret + "\n",
		// A bare value, as a truncated write leaves behind.
		secret + "\n",
		// An unterminated quote: go-ini echoes from the quote to end of file.
		"ncloud_secret_access_key = \"\"\"" + secret + "\n",
	} {
		path := writeCredentialFile(t, content)
		_, err := NewFileProvider(path).Retrieve(context.Background())
		if err == nil {
			t.Fatalf("expected %q to be rejected", content)
		}
		// Exact equality rather than a search for the secret: go-ini quotes a
		// different fragment for each shape -- a line, a value, a run to end of
		// file -- and searching for the one this test happens to plant ties the
		// assertion to that list. One known message cannot carry any of them.
		want := fmt.Sprintf("credential file %s could not be read or is not valid ini", path)
		if got := err.Error(); got != want {
			t.Errorf("error may only be the fixed message, got %q", got)
		}
	}
}

func TestAPIURLFromFile(t *testing.T) {
	path := writeCredentialFile(t, "secretmanager_api_url = https://example.com/api/v1\n")
	if got := APIURLFromFile(path); got != "https://example.com/api/v1" {
		t.Fatalf("got %q", got)
	}

	// A missing file yields an empty string so the caller can fall back.
	if got := APIURLFromFile(filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Fatalf("expected empty string for a missing file, got %q", got)
	}
}

// fakeMetadataServer serves the metadata v2 contract: a token is issued by PUT,
// and every data request must carry it. Requests without a valid token are
// answered 401, the way an instance restricted to v2 answers them, so every
// test built on this server also asserts that the provider speaks v2.
func fakeMetadataServer(t *testing.T, roleID, credBody string) *httptest.Server {
	t.Helper()
	const token = "session-token"

	mux := http.NewServeMux()
	mux.HandleFunc(metadataTokenPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ttl, err := strconv.Atoi(r.Header.Get(metadataTokenTTLHeader))
		if err != nil || ttl < 1 || ttl > 21600 {
			t.Errorf("%s: got %q, want 1..21600", metadataTokenTTLHeader, r.Header.Get(metadataTokenTTLHeader))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, token)
	})
	mux.HandleFunc(metadataCredsPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(metadataTokenHeader) != token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "Unauthorized.")
			return
		}
		switch r.URL.Path {
		case metadataCredsPath:
			_, _ = io.WriteString(w, roleID+"\n")
		case metadataCredsPath + roleID:
			_, _ = io.WriteString(w, credBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestServerRoleProvider_Retrieve(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	body := fmt.Sprintf(`{"Code":"Success","AccessKeyId":"ak","SecretAccessKey":"sk","Expiration":%q}`,
		exp.Format(time.RFC3339))
	srv := fakeMetadataServer(t, "role-1", body)

	v, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if v.AccessKey != "ak" || v.SecretKey != "sk" {
		t.Fatalf("got %+v", v)
	}
	if !v.Expiration.Equal(exp) {
		t.Fatalf("expiration: got %v want %v", v.Expiration, exp)
	}
}

// Named for what it does: every metadata path answers 404, so the failure is at
// the token step. The role listing is never reached -- the branch that handles
// a node with no role attached is covered by TestServerRoleProvider_EmptyRoleList.
func TestServerRoleProvider_MetadataPathsAbsent(t *testing.T) {
	srv := fakeMetadataServer(t, "role-1", "")
	_, err := NewServerRoleProvider(srv.URL + "/absent").Retrieve(context.Background())
	if err == nil {
		t.Fatal("expected error when the metadata API answers nothing")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should point at the token step, got %v", err)
	}
}

// Without a token endpoint there is nothing to fall back to: the provider does
// not retry the request as unauthenticated v1.
func TestServerRoleProvider_TokenEndpointUnavailable(t *testing.T) {
	var mu sync.Mutex
	var sawUnauthenticatedGet bool
	mux := http.NewServeMux()
	mux.HandleFunc(metadataTokenPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc(metadataCredsPath, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawUnauthenticatedGet = true
		mu.Unlock()
		_, _ = io.WriteString(w, "role-1\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background())
	if err == nil {
		t.Fatal("expected an error when no token can be issued")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should point at the token step, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if sawUnauthenticatedGet {
		t.Error("provider fell back to an unauthenticated v1 request")
	}
}

// A token endpoint can answer 200 with an error message instead of a token.
// Sending that as a token would fail later and point at the wrong step.
func TestServerRoleProvider_TokenEndpointReturnsMessage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(metadataTokenPath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "token issue failed\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if _, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background()); err == nil {
		t.Fatal("expected an error when the body is a message rather than a token")
	}
}

func TestServerRoleProvider_EmptyRoleList(t *testing.T) {
	srv := fakeMetadataServer(t, "", "")
	if _, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background()); err == nil {
		t.Fatal("expected error for an empty role list")
	}
}

// A 200 body on the credentials path is the access/secret key document, so a
// decode failure must not quote the byte it stopped on. This error reaches
// main.go's klog on the path where both sources fail and the pod crash-loops.
func TestServerRoleProvider_DecodeErrorDoesNotQuoteTheBody(t *testing.T) {
	const secret = "s3cret-value"
	srv := fakeMetadataServer(t, "role-1", secret)
	defer srv.Close()

	_, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	// Exact equality rather than a search: the decoder names one byte, and a
	// search for one byte finds it in any ordinary word.
	if got, want := err.Error(), "server role credentials are not valid JSON"; got != want {
		t.Fatalf("error may only be the fixed message, got %q", got)
	}
}

func TestServerRoleProvider_MissingExpiration(t *testing.T) {
	srv := fakeMetadataServer(t, "role-1", `{"Code":"Success","AccessKeyId":"ak","SecretAccessKey":"sk"}`)
	if _, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background()); err == nil {
		t.Fatal("expected error when Expiration is absent: temporary credentials would never refresh")
	}
}

func TestServerRoleProvider_AlreadyExpired(t *testing.T) {
	exp := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	body := fmt.Sprintf(`{"Code":"Success","AccessKeyId":"ak","SecretAccessKey":"sk","Expiration":%q}`,
		exp.Format(time.RFC3339))
	srv := fakeMetadataServer(t, "role-1", body)

	if _, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background()); err == nil {
		t.Fatal("expected error when Expiration is already in the past: it would cache, refresh, and loop forever")
	}
}

func TestServerRoleProvider_NonSuccessCode(t *testing.T) {
	srv := fakeMetadataServer(t, "role-1", `{"Code":"Failure"}`)
	if _, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background()); err == nil {
		t.Fatal("expected error for a non-Success Code")
	}
}

type fakeProvider struct {
	name  string
	value Value
	err   error
	calls int
}

func (f *fakeProvider) Name() string { return f.name }

func (f *fakeProvider) Retrieve(context.Context) (Value, error) {
	f.calls++
	return f.value, f.err
}

func TestStaticSource(t *testing.T) {
	v, err := NewStaticSource("ak", "sk").Credentials(context.Background())
	if err != nil || v.AccessKey != "ak" || v.SecretKey != "sk" {
		t.Fatalf("got %+v, err %v", v, err)
	}
	if _, err := NewStaticSource("", "").Credentials(context.Background()); err == nil {
		t.Fatal("expected error for empty static credentials")
	}
}

func TestChainSource_FirstProviderWins(t *testing.T) {
	first := &fakeProvider{name: "first", value: Value{AccessKey: "a1", SecretKey: "s1"}}
	second := &fakeProvider{name: "second", value: Value{AccessKey: "a2", SecretKey: "s2"}}
	chain := NewChainSource(first, second)

	v, err := chain.Credentials(context.Background())
	if err != nil || v.AccessKey != "a1" {
		t.Fatalf("got %+v, err %v", v, err)
	}
	if second.calls != 0 {
		t.Fatalf("second provider must not be consulted, calls=%d", second.calls)
	}
	if chain.ProviderName() != "first" {
		t.Fatalf("ProviderName: got %q", chain.ProviderName())
	}

	// Non-expiring values are cached, so the provider is not called again.
	if _, err := chain.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if first.calls != 1 {
		t.Fatalf("expected the value to be cached, calls=%d", first.calls)
	}
}

func TestChainSource_FallsBackWhenFirstFails(t *testing.T) {
	first := &fakeProvider{name: "first", err: errors.New("nope")}
	second := &fakeProvider{name: "second", value: Value{AccessKey: "a2", SecretKey: "s2"}}
	chain := NewChainSource(first, second)

	v, err := chain.Credentials(context.Background())
	if err != nil || v.AccessKey != "a2" {
		t.Fatalf("got %+v, err %v", v, err)
	}
	if chain.ProviderName() != "second" {
		t.Fatalf("ProviderName: got %q", chain.ProviderName())
	}
}

func TestChainSource_AllProvidersFail(t *testing.T) {
	chain := NewChainSource(
		&fakeProvider{name: "first", err: errors.New("nope")},
		&fakeProvider{name: "second", err: errors.New("also nope")},
	)
	if _, err := chain.Credentials(context.Background()); err == nil {
		t.Fatal("expected an error when every provider fails")
	}
}

func TestChainSource_RefreshesBeforeExpiry(t *testing.T) {
	base := time.Now()
	p := &fakeProvider{name: "role", value: Value{AccessKey: "a1", SecretKey: "s1", Expiration: base.Add(30 * time.Minute)}}
	chain := NewChainSource(p)
	chain.now = func() time.Time { return base }

	if _, err := chain.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.calls != 1 {
		t.Fatalf("calls=%d", p.calls)
	}

	// Still outside the refresh margin: served from cache.
	chain.now = func() time.Time { return base.Add(15 * time.Minute) }
	if _, err := chain.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.calls != 1 {
		t.Fatalf("expected cache hit, calls=%d", p.calls)
	}

	// Inside the 10-minute margin: refreshed.
	p.value = Value{AccessKey: "a2", SecretKey: "s2", Expiration: base.Add(90 * time.Minute)}
	chain.now = func() time.Time { return base.Add(25 * time.Minute) }
	v, err := chain.Credentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.AccessKey != "a2" {
		t.Fatalf("expected refreshed credentials, got %+v", v)
	}
	if p.calls != 2 {
		t.Fatalf("calls=%d", p.calls)
	}
}

func TestChainSource_KeepsLastGoodWhenRefreshFails(t *testing.T) {
	base := time.Now()
	p := &fakeProvider{name: "role", value: Value{AccessKey: "a1", SecretKey: "s1", Expiration: base.Add(30 * time.Minute)}}
	chain := NewChainSource(p)
	chain.now = func() time.Time { return base }

	if _, err := chain.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Refresh fails while the cached value is still valid.
	p.err = errors.New("metadata unavailable")
	chain.now = func() time.Time { return base.Add(25 * time.Minute) }
	v, err := chain.Credentials(context.Background())
	if err != nil {
		t.Fatalf("expected the cached value to be served, got %v", err)
	}
	if v.AccessKey != "a1" {
		t.Fatalf("got %+v", v)
	}

	// Past the actual expiration the error surfaces.
	chain.now = func() time.Time { return base.Add(31 * time.Minute) }
	if _, err := chain.Credentials(context.Background()); err == nil {
		t.Fatal("expected an error once the cached value has expired")
	}
}

func TestChainSource_ConcurrentAccess(t *testing.T) {
	chain := NewChainSource(&fakeProvider{name: "first", value: Value{AccessKey: "a1", SecretKey: "s1"}})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := chain.Credentials(context.Background()); err != nil {
				t.Errorf("Credentials: %v", err)
			}
			_ = chain.ProviderName()
		}()
	}
	wg.Wait()
}

// A metadata failure used to read "returned HTTP 401" and nothing else, which
// is the same sentence for a role that is not attached, a policy that is
// missing and a token that expired. The body says which -- bounded, because the
// read limit above it is a megabyte and this goes to the node's provider log on
// every failed mount.
func TestServerRoleProvider_ErrorQuotesTheBody(t *testing.T) {
	t.Run("body is quoted", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc(metadataTokenPath, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "Unauthorized.")
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		_, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background())
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "Unauthorized.") {
			t.Errorf("error should quote what the API said, got %v", err)
		}
	})

	t.Run("body is bounded", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc(metadataTokenPath, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, strings.Repeat("x", 64<<10))
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		_, err := NewServerRoleProvider(srv.URL).Retrieve(context.Background())
		if err == nil {
			t.Fatal("expected an error")
		}
		if n := strings.Count(err.Error(), "x"); n > 1<<10 {
			t.Errorf("error carried %d bytes of the body, want at most %d", n, 1<<10)
		}
	})
}
