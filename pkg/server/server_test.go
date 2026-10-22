// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	"github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/credentials"
)

// secretManagerStub serves one secret named "my-secret" whose value is a JSON
// document, which is what the Usage section of the README describes.
func secretManagerStub(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1,
			"secretList": []map[string]string{{"secretId": "sid", "secretName": "my-secret"}},
		}})
	})
	mux.HandleFunc("/secrets/sid/values", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"decryptedSecretChain": map[string]string{"active": `{"id":"alice","pw":"s3cret"}`},
		}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestServer(t *testing.T, apiURL string) *CSIDriverProviderServer {
	t.Helper()
	u, err := url.Parse(apiURL)
	if err != nil {
		t.Fatalf("parse %q: %v", apiURL, err)
	}
	return NewServer(u, credentials.NewStaticSource("ak", "sk"))
}

func mountRequest(t *testing.T, objects string) *v1alpha1.MountRequest {
	t.Helper()
	attrib, err := json.Marshal(map[string]string{
		"csi.storage.k8s.io/pod.name":      "my-pod",
		"csi.storage.k8s.io/pod.namespace": "default",
		"objects":                          objects,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &v1alpha1.MountRequest{Attributes: string(attrib), Permission: "420"}
}

// The example in examples/secretproviderclass.yaml mounts one secret into two
// files. The driver folds ObjectVersion into a map keyed by Id, so those two
// entries have to carry distinct Ids or one of them disappears.
func TestMount_OneSecretTwoPaths(t *testing.T) {
	srv := secretManagerStub(t)
	s := newTestServer(t, srv.URL)

	resp, err := s.Mount(context.Background(), mountRequest(t, `
- objectName: my-secret
  objectType: secretmanager
  path: whole.txt
- objectName: my-secret
  objectType: secretmanager
  secretKey: id
  path: id.txt
`))
	if err != nil {
		t.Fatalf("mount: %v", err)
	}

	files := map[string]string{}
	for _, f := range resp.GetFiles() {
		files[f.GetPath()] = string(f.GetContents())
		if f.GetMode() != 420 {
			t.Errorf("file %q: mode %d, want 420", f.GetPath(), f.GetMode())
		}
	}
	if len(files) != 2 || files["whole.txt"] != `{"id":"alice","pw":"s3cret"}` || files["id.txt"] != "alice" {
		t.Fatalf("unexpected files: %v", files)
	}

	ids := map[string]bool{}
	for _, ov := range resp.GetObjectVersion() {
		if ids[ov.GetId()] {
			t.Fatalf("duplicate ObjectVersion id %q -- the driver would fold these into one", ov.GetId())
		}
		ids[ov.GetId()] = true
	}
	if len(ids) != 2 {
		t.Fatalf("got %d distinct object version ids, want 2: %v", len(ids), ids)
	}
}

func TestMount_RejectsBadConfig(t *testing.T) {
	srv := secretManagerStub(t)
	s := newTestServer(t, srv.URL)

	for _, tc := range []struct{ name, objects string }{
		{"empty entry", "-\n"},
		{"unknown objectType", "- objectName: my-secret\n  objectType: nope\n  path: a.txt\n"},
		{"missing path", "- objectName: my-secret\n  objectType: secretmanager\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning an error: %v", r)
				}
			}()
			if _, err := s.Mount(context.Background(), mountRequest(t, tc.objects)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// A secret that is not in Secret Manager must surface as an error, never as an
// empty file.
func TestMount_SecretNotFound(t *testing.T) {
	srv := secretManagerStub(t)
	s := newTestServer(t, srv.URL)

	_, err := s.Mount(context.Background(), mountRequest(t,
		"- objectName: absent\n  objectType: secretmanager\n  path: a.txt\n"))
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("expected an error naming the secret, got %v", err)
	}
}

func TestVersion(t *testing.T) {
	s := newTestServer(t, "https://example.invalid/api/v1")
	resp, err := s.Version(context.Background(), &v1alpha1.VersionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVersion() != "v1alpha1" || resp.GetRuntimeName() != "secrets-store-csi-driver-provider-ncp" {
		t.Fatalf("unexpected version response: %+v", resp)
	}
	if resp.GetRuntimeVersion() == "" {
		t.Error("RuntimeVersion is empty; ldflags injection has no default to fall back on")
	}
}

// Referencing one secret from several entries must not refetch it. The shipped
// example does exactly this, and it used to cost a full name lookup plus a
// value fetch per entry.
func TestMount_FetchesEachSecretOnce(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	count := func(key string) {
		mu.Lock()
		calls[key]++
		mu.Unlock()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		count("list")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"currentPageNo": 1, "totalPageNo": 1,
			"secretList": []map[string]string{
				{"secretId": "sid-a", "secretName": "secret-a"},
				{"secretId": "sid-b", "secretName": "secret-b"},
			},
		}})
	})
	for id, value := range map[string]string{"sid-a": `{"id":"alice"}`, "sid-b": "plain-b"} {
		id, value := id, value
		mux.HandleFunc("/secrets/"+id+"/values", func(w http.ResponseWriter, r *http.Request) {
			count("values:" + id)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"decryptedSecretChain": map[string]string{"active": value},
			}})
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := newTestServer(t, srv.URL)
	resp, err := s.Mount(context.Background(), mountRequest(t, `
- objectName: secret-a
  objectType: secretmanager
  path: whole.txt
- objectName: secret-a
  objectType: secretmanager
  secretKey: id
  path: id.txt
- objectName: secret-b
  objectType: secretmanager
  path: b.txt
`))
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if len(resp.GetFiles()) != 3 {
		t.Fatalf("got %d files, want 3", len(resp.GetFiles()))
	}

	mu.Lock()
	defer mu.Unlock()
	// Two distinct secrets: two name lookups and two value fetches, not three.
	want := map[string]int{"list": 2, "values:sid-a": 1, "values:sid-b": 1}
	for key, n := range want {
		if calls[key] != n {
			t.Errorf("%s called %d times, want %d (all calls: %v)", key, calls[key], n, calls)
		}
	}
}
