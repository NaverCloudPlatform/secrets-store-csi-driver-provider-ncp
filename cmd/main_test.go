// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package main

import (
	"errors"
	"flag"
	"io"
	"maps"
	"os"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v2"
	"k8s.io/klog/v2"
)

// These four rules are the provider's only check that it is about to send a
// signed request somewhere sensible. They run once, at startup, and a failure
// takes the node's provider down, so each one is worth a case.
func TestParseAPIURL(t *testing.T) {
	for _, tc := range []struct {
		name, raw, wantErr string
	}{
		{"https", "https://ocapi-kr.ncloud.com/secretmanager/api/v1", ""},
		{"https without a path", "https://ocapi-kr.ncloud.com", ""},
		{"port", "https://ocapi-kr.ncloud.com:8443/api/v1", ""},

		{"http", "http://ocapi-kr.ncloud.com/api/v1", "https"},
		{"no scheme", "ocapi-kr.ncloud.com/api/v1", "absolute"},
		{"scheme only", "https://", "absolute"},
		{"empty", "", "absolute"},
		{"userinfo", "https://ak:sk@ocapi-kr.ncloud.com/api/v1", "userinfo"},
		// Checked before the scheme, so that a credential in a plain-http URL
		// is not reported by a rule that quotes what it saw.
		{"userinfo over http", "http://ak:sk@ocapi-kr.ncloud.com/api/v1", "userinfo"},
		{"query", "https://ocapi-kr.ncloud.com/api/v1?x=1", "base URL"},
		{"fragment", "https://ocapi-kr.ncloud.com/api/v1#f", "base URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := parseAPIURL(tc.raw)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected it to pass: %v", err)
				}
				if u == nil {
					t.Fatal("no URL returned")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error, got %v", u)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// A rejected URL is the kind most likely to hold a credential, and the error is
// logged, so no message may echo the URL back.
func TestParseAPIURL_ErrorsDoNotQuoteTheURL(t *testing.T) {
	const secret = "s3cret-key"
	for _, raw := range []string{
		"https://ak:" + secret + "@host/api",
		"http://ak:" + secret + "@host/api",
		"://" + secret,
	} {
		_, err := parseAPIURL(raw)
		if err == nil {
			t.Fatalf("expected %q to be rejected", raw)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaked the URL: %v", err)
		}
	}
}

// Every endpoint the repository hands a user has to pass the check that runs at
// startup. A URL that does not is a provider that will not come up, found by
// whoever copied it rather than here.
func TestExampleAndDocumentedURLsPass(t *testing.T) {
	for _, f := range []string{"../examples/configure.example", "../README.md"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var n int
		for _, m := range regexp.MustCompile(`https?://[^\s"'`+"`"+`|)]+`).FindAllString(string(raw), -1) {
			// Only this API's endpoints. The README links to NCP documentation
			// too, and matching those would both miss the endpoints going away
			// and report a documentation link that grew a query string.
			if !strings.Contains(m, "secretmanager") {
				continue
			}
			n++
			if _, err := parseAPIURL(m); err != nil {
				t.Errorf("%s offers %q, which the provider refuses at startup: %v", f, m, err)
			}
		}
		if n == 0 {
			t.Errorf("%s: found no endpoint to check; this test is looking in the wrong place", f)
		}
	}
}

// The manifest is what users apply, and its server-role option is a commented
// args line that works only when removing the "#" leaves it in the image
// column. A comment realigned by one space would put it back to breaking the
// YAML or doing nothing, with no other check in the tree to notice.
func TestDeployManifestArgsUncomment(t *testing.T) {
	raw, err := os.ReadFile("../deploy/secrets-store-csi-driver-provider-ncp.yaml")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(raw), "#args:") {
		t.Fatal("manifest no longer carries a commented args line; update this test")
	}
	for _, tc := range []struct {
		name     string
		manifest string
		wantArgs bool
	}{
		{"as shipped", string(raw), false},
		{"args uncommented", strings.Replace(string(raw), "#args:", "args:", 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			docs := 0
			dec := yaml.NewDecoder(strings.NewReader(tc.manifest))
			for {
				var doc struct {
					Kind string
					Spec struct {
						Template struct {
							Spec struct {
								Containers []struct{ Args []string }
							}
						}
					}
				}
				err := dec.Decode(&doc)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("document %d: %v", docs, err)
				}
				docs++
				if doc.Kind == "DaemonSet" {
					args = doc.Spec.Template.Spec.Containers[0].Args
				}
			}
			if docs != 2 {
				t.Fatalf("got %d documents, want the ServiceAccount and the DaemonSet", docs)
			}
			if got := len(args) > 0; got != tc.wantArgs {
				t.Fatalf("container args = %q", args)
			}
			if !tc.wantArgs {
				return
			}
			// Parsed against the flags main registers, so a renamed flag fails
			// here and not as "flag provided but not defined" on a node.
			fs := flag.NewFlagSet("provider", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			klog.InitFlags(fs) // main registers klog's flags on the same set
			_, _, apiURL := defineFlags(fs)
			if err := fs.Parse(args); err != nil {
				t.Fatalf("the documented args do not parse: %v", err)
			}
			if _, err := parseAPIURL(*apiURL); err != nil {
				t.Fatalf("the documented URL is refused at startup: %v", err)
			}
		})
	}
}

// Clusters that installed a pre-release build, before this repository was
// public, run a DaemonSet with these names, and moving them to this manifest
// only works while the names match. A credential
// Secret under another name is not found however the manifest is applied, so
// the provider exits for want of an API URL on every node. A container or
// volume under another name matters to a server-side apply that takes the
// object over, as an addon would: a list entry another manager owns is kept,
// so the new one is added beside the old. kubectl apply replaces it instead.
func TestDeployManifestKeepsInstalledNames(t *testing.T) {
	raw, err := os.ReadFile("../deploy/secrets-store-csi-driver-provider-ncp.yaml")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	for {
		var doc struct {
			Kind     string
			Metadata struct{ Name, Namespace string }
			Spec     struct {
				Template struct {
					Spec struct {
						Containers []struct{ Name string }
						Volumes    []struct {
							Name   string
							Secret struct {
								SecretName string `yaml:"secretName"`
							}
						}
					}
				}
			}
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			t.Fatal("no DaemonSet in the manifest")
		}
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if doc.Kind != "DaemonSet" {
			continue
		}
		const name = "secrets-store-csi-driver-provider-ncp"
		if doc.Metadata.Name != name || doc.Metadata.Namespace != "kube-system" {
			t.Errorf("DaemonSet is %s/%s, want kube-system/%s", doc.Metadata.Namespace, doc.Metadata.Name, name)
		}
		pod := doc.Spec.Template.Spec
		if len(pod.Containers) != 1 || pod.Containers[0].Name != name {
			t.Errorf("containers = %+v, want one named %s", pod.Containers, name)
		}
		// Volume name to the Secret it mounts; the socket volume is a hostPath.
		vols := map[string]string{}
		for _, v := range pod.Volumes {
			vols[v.Name] = v.Secret.SecretName
		}
		want := map[string]string{"providervol": "", "credentials": "ncp-secrets-store-credentials"}
		if !maps.Equal(vols, want) {
			t.Errorf("volumes = %v, want %v", vols, want)
		}
		return
	}
}
