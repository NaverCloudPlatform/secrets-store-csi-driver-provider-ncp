// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package provider

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v2"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

func mountReq(t *testing.T, attrib map[string]string) *v1alpha1.MountRequest {
	t.Helper()
	b, _ := json.Marshal(attrib)
	return &v1alpha1.MountRequest{Attributes: string(b), Permission: "420"}
}

// The driver forwards nodePublishSecretRef in MountRequest.Secrets. What an
// absent one looks like is what decides whether this refusal reaches
// deployments that never asked for per-pod credentials: the driver marshals the
// map straight from the CSI request, and an unset proto map is nil, which
// encodes as "null" rather than "{}".
func TestParseConfig_RefusesPerPodSecrets(t *testing.T) {
	req := func(secrets string) *v1alpha1.MountRequest {
		r := mountReq(t, map[string]string{
			"csi.storage.k8s.io/pod.name":      "p",
			"csi.storage.k8s.io/pod.namespace": "ns",
			"objects":                          "- objectName: s1\n  objectType: secretmanager\n  path: s1.txt\n",
		})
		r.Secrets = secrets
		return r
	}

	for _, secrets := range []string{
		"",     // the field left unset
		"null", // no nodePublishSecretRef, as the driver encodes it
		"{}",
		// Kubelet carries the pod's service account tokens in this same field
		// where the CSIDriver asks for it. This provider never reads them, and
		// refusing them would refuse every mount on such a cluster.
		`{"csi.storage.k8s.io/serviceAccount.tokens":"{\"aud\":{\"token\":\"t\"}}"}`,
		// Any reserved key, not just that one: a Secret's data keys cannot hold
		// a "/", so nothing a ref carries can look like this.
		`{"csi.storage.k8s.io/some.future.key":"v"}`,
	} {
		if _, err := ParseConfig(req(secrets)); err != nil {
			t.Errorf("Secrets %q must still mount: %v", secrets, err)
		}
	}

	const want = "nodePublishSecretRef is set, but this provider signs every request with one cluster-wide credential"
	for _, secrets := range []string{
		`{"ncloud_access_key_id":"AK","ncloud_secret_access_key":"s3cret"}`,
		// One known key does not excuse the rest.
		`{"csi.storage.k8s.io/serviceAccount.tokens":"t","ncloud_secret_access_key":"s3cret"}`,
	} {
		_, err := ParseConfig(req(secrets))
		if err == nil {
			t.Fatalf("Secrets %q must be refused", secrets)
		}
		// The field is the referenced Secret's data, and this error reaches the
		// provider log and the pod event.
		if got := err.Error(); got != want {
			t.Errorf("error may only be the fixed message, got %q", got)
		}
	}

	_, err := ParseConfig(req(`{"ncloud_secret_access_key":"s3cret`))
	if err == nil {
		t.Fatal("a Secrets field that does not decode must be refused")
	}
	if got := err.Error(); got != "nodePublishSecretRef could not be read" {
		t.Errorf("error may only be the fixed message, got %q", got)
	}
}

// A document well inside the 128 KiB cap still produces a parse error of
// several MiB: yaml names every element it could not decode, one line each.
// That string is logged by the provider, sent as the gRPC status, logged again
// by the driver, and repeated on every kubelet retry, so its size is paid four
// times over and again on each backoff.
func TestParseConfig_ParseErrorIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("[a")
	for b.Len() < maxObjectsBytes-3 {
		b.WriteString(",a")
	}
	b.WriteString("]")
	doc := b.String()
	if len(doc) > maxObjectsBytes {
		t.Fatalf("document is %d bytes, which the size cap would refuse first", len(doc))
	}

	_, err := ParseConfig(mountReq(t, map[string]string{
		"csi.storage.k8s.io/pod.name":      "p",
		"csi.storage.k8s.io/pod.namespace": "ns",
		"objects":                          doc,
	}))
	if err == nil {
		t.Fatal("expected the document to be refused")
	}
	msg := err.Error()
	// The trimmed message plus the line that says what was dropped.
	if len(msg) > maxParseErrorBytes+128 {
		t.Errorf("parse error is %d bytes, over the %d it is capped at", len(msg), maxParseErrorBytes)
	}
	// The first complaint is the one anybody reads, so it has to survive.
	if !strings.HasPrefix(msg, "failed to parse objects: yaml: unmarshal errors:\n  line 1:") {
		t.Errorf("the first complaint must lead, got %q", msg[:min(len(msg), 80)])
	}
	if !strings.Contains(msg, "more lines") {
		t.Errorf("a trimmed error must say what it dropped, got %q", msg[max(0, len(msg)-80):])
	}
}

// An error that fits is passed through whole: trimming exists for the flood,
// not for the ordinary mistake.
func TestParseConfig_ShortParseErrorIsWhole(t *testing.T) {
	_, err := ParseConfig(mountReq(t, map[string]string{
		"csi.storage.k8s.io/pod.name":      "p",
		"csi.storage.k8s.io/pod.namespace": "ns",
		"objects":                          "- 1\n",
	}))
	if err == nil {
		t.Fatal("expected the document to be refused")
	}
	if strings.Contains(err.Error(), "more lines") {
		t.Errorf("a short error must not be trimmed, got %q", err)
	}
}

func TestParseConfig(t *testing.T) {
	base := map[string]string{
		"csi.storage.k8s.io/pod.name":      "p",
		"csi.storage.k8s.io/pod.namespace": "ns",
	}
	with := func(objects string) map[string]string {
		m := map[string]string{"objects": objects}
		for k, v := range base {
			m[k] = v
		}
		return m
	}

	cfg, err := ParseConfig(mountReq(t, with("- objectName: s1\n  objectType: secretmanager\n  path: s1.txt\n")))
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if cfg.PodName != "p" || cfg.PodNamespace != "ns" || len(cfg.ObjectParams) != 1 || cfg.ObjectParams[0].Path != "s1.txt" {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}

	// Omitting secretKey mounts the whole secret, and a named one is extracted:
	// both shapes are in the shipped examples and in existing deployments.
	cfg, err = ParseConfig(mountReq(t, with("- objectName: s1\n  objectType: secretmanager\n  path: s1.txt\n  secretKey: id\n")))
	if err != nil {
		t.Fatalf("valid secretKey: %v", err)
	}
	if cfg.ObjectParams[0].SecretKey != "id" {
		t.Fatalf("secretKey not kept: %+v", cfg.ObjectParams[0])
	}

	if _, err := ParseConfig(mountReq(t, with("- objectName: s1\n  objectType: bogus\n  path: s1.txt\n"))); err == nil {
		t.Fatal("expected error for invalid objectType")
	}

	if _, err := ParseConfig(mountReq(t, base)); err == nil {
		t.Fatal("expected error for missing objects")
	}
}

// Malformed object lists must be rejected with an error. An empty list entry
// used to decode to nil and panic on the first field read, which killed the
// provider for every pod on the node; an unknown field used to be dropped, so
// a typo in secretKey quietly mounted the whole secret instead of one value.
func TestParseConfig_RejectsMalformedObjects(t *testing.T) {
	attrib := func(objects string) map[string]string {
		return map[string]string{
			"csi.storage.k8s.io/pod.name":      "p",
			"csi.storage.k8s.io/pod.namespace": "ns",
			"objects":                          objects,
		}
	}

	for _, tc := range []struct{ name, objects, want string }{
		{"nil entry", "- null\n", "is empty"},
		{"bare dash", "-\n", ""},
		{"entry after a valid one", "- objectName: s1\n  objectType: secretmanager\n  path: s1.txt\n- null\n", ""},
		{"empty list", "[]\n", "at least one entry"},
		{"misspelled secretKey", "- objectName: s1\n  objectType: secretmanager\n  secretKye: id\n  path: s1.txt\n", ""},
		{"unknown field", "- objectName: s1\n  objectType: secretmanager\n  path: s1.txt\n  extra: x\n", ""},
		{"duplicate field", "- objectName: s1\n  objectName: s2\n  objectType: secretmanager\n  path: s1.txt\n", ""},
		{"missing path", "- objectName: s1\n  objectType: secretmanager\n", "objects[0]: objectName"},
		{"invalid objectType", "- objectName: s1\n  objectType: bogus\n  path: a.txt\n", "objects[0]: invalid objectType"},
		// The driver keys files by path, so a repeat silently drops one entry --
		// but only after both secrets have been fetched.
		{"duplicate path", "- objectName: s1\n  objectType: secretmanager\n  path: same.txt\n" +
			"- objectName: s2\n  objectType: secretmanager\n  path: same.txt\n", "is already used by"},
		// Escaping paths are rejected before anything is read out of Secret
		// Manager, not left for the driver to refuse after the fact.
		{"parent-relative path", "- objectName: s1\n  objectType: secretmanager\n  path: ../escape.txt\n", "clean relative path"},
		{"escaping path", "- objectName: s1\n  objectType: secretmanager\n  path: a/../../b.txt\n", ""},
		{"absolute path", "- objectName: s1\n  objectType: secretmanager\n  path: /abs.txt\n", ""},
		{"unclean path", "- objectName: s1\n  objectType: secretmanager\n  path: ./a.txt\n", ""},
		{"dot path", "- objectName: s1\n  objectType: secretmanager\n  path: \".\"\n", ""},
		// Each entry costs at least a paged lookup and a value fetch, so the
		// list has an upper bound.
		{"too many objects", strings.Repeat("- objectName: s\n  objectType: secretmanager\n  path: p\n", maxObjectsPerMount+1), "at most"},
		// secretKey written with nothing in it -- a template that rendered
		// blank. Falling through to the no-secretKey path would mount every
		// field of the secret where one field was asked for.
		{"empty secretKey", "- objectName: s1\n  objectType: secretmanager\n  path: s1.txt\n  secretKey: \"\"\n", "secretKey is set but has no value"},
		{"null secretKey", "- objectName: s1\n  objectType: secretmanager\n  path: s1.txt\n  secretKey:\n", "secretKey is set but has no value"},
		{"tilde secretKey", "- objectName: s1\n  objectType: secretmanager\n  path: s1.txt\n  secretKey: ~\n", "secretKey is set but has no value"},
		{"NULL secretKey", "- objectName: s1\n  objectType: secretmanager\n  path: s1.txt\n  secretKey: NULL\n", "secretKey is set but has no value"},
		// An entry that is not a mapping reaches the struct decode first.
		{"scalar entry", "- hello\n", ""},
		{"sequence entry", "- [a, b]\n", ""},
		// A name cannot be a file in one entry and a directory in another: the
		// driver fails the whole mount on whichever it reaches second, after
		// every secret has been fetched.
		{"path under a file", "- objectName: s1\n  objectType: secretmanager\n  path: a\n" +
			"- objectName: s2\n  objectType: secretmanager\n  path: a/b\n", "is under path"},
		{"file under a path", "- objectName: s1\n  objectType: secretmanager\n  path: a/b\n" +
			"- objectName: s2\n  objectType: secretmanager\n  path: a\n", "is a directory"},
		{"file under a deeper path", "- objectName: s1\n  objectType: secretmanager\n  path: a/b/c\n" +
			"- objectName: s2\n  objectType: secretmanager\n  path: a\n", "is a directory"},
		// The driver keeps these names for itself in the mount directory, and
		// refuses them only after every secret has been fetched.
		{"path starting with ..", "- objectName: s1\n  objectType: secretmanager\n  path: ..data\n", "must not start with"},
		{"overlong name", "- objectName: s1\n  objectType: secretmanager\n  path: " + strings.Repeat("n", maxFileNameLength+1) + "\n", "longer than"},
		{"overlong name deeper", "- objectName: s1\n  objectType: secretmanager\n  path: d/" + strings.Repeat("n", maxFileNameLength+1) + "\n", "longer than"},
		{"overlong path", "- objectName: s1\n  objectType: secretmanager\n  path: " +
			strings.TrimSuffix(strings.Repeat(strings.Repeat("d", 100)+"/", 42), "/") + "\n", "at most"},
		// yaml stops at the first document, so everything past a "---" used to
		// be dropped without a word and the pod started with files missing.
		{"second document", "- objectName: s1\n  objectType: secretmanager\n  path: a.txt\n" +
			"---\n- objectName: s2\n  objectType: secretmanager\n  path: b.txt\n", "single YAML document"},
		{"leading document separator", "---\n- objectName: s1\n  objectType: secretmanager\n  path: a.txt\n" +
			"---\n- objectName: s2\n  objectType: secretmanager\n  path: b.txt\n", "single YAML document"},
		// Loses no entry, and is still refused: see the note in ParseConfig.
		{"trailing document separator", "- objectName: s1\n  objectType: secretmanager\n  path: a.txt\n---\n", "single YAML document"},
		// Otherwise valid, so it is refused for its size alone -- and before it
		// is parsed, which is what the size would have cost.
		{"oversized objects", "- objectName: " + strings.Repeat("s", maxObjectsBytes) +
			"\n  objectType: secretmanager\n  path: s1.txt\n", "at most"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning an error: %v", r)
				}
			}()
			_, err := ParseConfig(mountReq(t, attrib(tc.objects)))
			if err == nil {
				t.Fatal("expected an error")
			}
			// Without this the strict decoder's own complaint would pass for
			// the check the case is actually about.
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// An entry error quotes the entry's own fields, and nothing bounds objectType
// or objectName, while an unclean path is quoted before its length is checked.
// Unclipped, one field is most of the document, sent out on every retry.
func TestParseConfig_QuotedFieldsAreClipped(t *testing.T) {
	long := strings.Repeat("x", maxObjectsBytes/2)
	// 35 names of 100 bytes: clean, and under maxPathLength with room for one
	// more name of any legal length.
	deep := strings.TrimSuffix(strings.Repeat(strings.Repeat("d", 100)+"/", 35), "/")
	entry := func(name, path string) string {
		return "- objectName: " + name + "\n  objectType: secretmanager\n  path: " + path + "\n"
	}
	for _, tc := range []struct{ name, objects, want string }{
		{"objectType", "- objectName: s1\n  objectType: " + long + "\n  path: a\n", "invalid objectType"},
		{"objectName", "- objectName: " + long + "\n  objectType: secretmanager\n", "must be set"},
		{"unclean path", entry("s1", "./"+long), "clean relative path"},
		// A path within its 4096-byte limit is still quoted by the checks after
		// it, and one of them quotes two.
		{"overlong name in a long path", entry("s1", deep+"/"+strings.Repeat("n", maxFileNameLength+1)), "longer than"},
		{"long path starting with ..", entry("s1", "..x/"+deep), "must not start with"},
		{"long duplicate path", entry("s1", deep) + entry("s2", deep), "already used by"},
		{"long path under a file", entry("s1", deep) + entry("s2", deep+"/f"), "is under path"},
		{"long file under a path", entry("s1", deep+"/f") + entry("s2", deep), "is a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig(mountReq(t, map[string]string{
				"csi.storage.k8s.io/pod.name":      "p",
				"csi.storage.k8s.io/pod.namespace": "ns",
				"objects":                          tc.objects,
			}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got: %.200v", tc.want, err)
			}
			if n := len(err.Error()); n > 1<<10 {
				t.Fatalf("error is %d bytes, want it clipped", n)
			}
		})
	}
}

// The size gate is the only limit with no boundary pinned by the shapes above,
// and it is checked before the parser runs, so a byte on either side of it
// takes a different path entirely. Written as literals rather than as
// maxObjectsBytes, so that raising the constant fails here instead of moving
// the boundary along with the test.
func TestParseConfig_ObjectsSizeBoundary(t *testing.T) {
	attrib := func(objects string) map[string]string {
		return map[string]string{
			"csi.storage.k8s.io/pod.name":      "p",
			"csi.storage.k8s.io/pod.namespace": "ns",
			"objects":                          objects,
		}
	}
	const entry = "- objectType: secretmanager\n  objectName: s\n  path: p\n"
	atCap := entry + "# " + strings.Repeat("x", 131072-len(entry)-3) + "\n"
	if len(atCap) != 131072 {
		t.Fatalf("built a %d byte document, want exactly 131072", len(atCap))
	}

	if _, err := ParseConfig(mountReq(t, attrib(atCap))); err != nil {
		t.Fatalf("a document exactly at the cap must still parse: %v", err)
	}
	if _, err := ParseConfig(mountReq(t, attrib(atCap+" "))); err == nil ||
		!strings.Contains(err.Error(), "bytes, at most") {
		// "at most" alone would also match the entry cap's message.
		t.Fatalf("one byte over the cap must be refused for its size, got %v", err)
	}

	// The shape the cap is sized on: a node every two bytes, and a decoder
	// error line per element. It has to come back as an error -- gRPC does not
	// recover a handler panic, so one of these would take the node's provider
	// down with it.
	// 3 + 2N is always odd, so this shape cannot land on the cap exactly:
	// 131071 is the largest flow sequence that fits under it.
	flow := "[a" + strings.Repeat(",a", (131072-3)/2) + "]"
	if len(flow) != 131071 {
		t.Fatalf("flow document is %d bytes, want 131071", len(flow))
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on the densest document the cap accepts: %v", r)
		}
	}()
	_, err := ParseConfig(mountReq(t, attrib(flow)))
	// Naming the parser's own failure, because a size refusal here would mean
	// the case never reached the parser -- which is the whole cost this cap is
	// sized against.
	if err == nil || !strings.Contains(err.Error(), "failed to parse objects") {
		t.Fatalf("the densest document under the cap must fail in the parser, got %v", err)
	}
}

// Shapes that must keep parsing. A merge key with an override is the one that
// matters: rejecting a secretKey written empty needs to know whether the field
// was written at all, and reading that back off the document is what broke this
// -- a strict decode counts the fields a merge key supplied as already set, so
// overriding one read as a duplicate.
func TestParseConfig_AcceptsValidObjects(t *testing.T) {
	attrib := func(objects string) map[string]string {
		return map[string]string{
			"csi.storage.k8s.io/pod.name":      "p",
			"csi.storage.k8s.io/pod.namespace": "ns",
			"objects":                          objects,
		}
	}

	for _, tc := range []struct {
		name, objects string
		want          []string // secretKey per entry, in order
	}{
		{"no secretKey", "- objectName: s1\n  objectType: secretmanager\n  path: a.txt\n", []string{""}},
		// One document that merely opens with a separator is still one document,
		// and "..." ends it without starting another.
		{"single document with a separator", "---\n- objectName: s1\n  objectType: secretmanager\n  path: a.txt\n", []string{""}},
		{"explicit end of document", "- objectName: s1\n  objectType: secretmanager\n  path: a.txt\n...\n", []string{""}},
		// "cert.pem" shares a prefix with "cert" without being inside it. The
		// element boundary in isUnder is what tells them apart, and dropping it
		// would turn the commonest pair of names in a mount into a collision.
		{"sibling names sharing a prefix", "- objectName: s1\n  objectType: secretmanager\n  path: cert\n" +
			"- objectName: s2\n  objectType: secretmanager\n  path: cert.pem\n", []string{"", ""}},
		{"sibling names sharing a prefix, deeper", "- objectName: s1\n  objectType: secretmanager\n  path: d/db\n" +
			"- objectName: s2\n  objectType: secretmanager\n  path: d/db-password\n", []string{"", ""}},
		{"merge key", "- &b\n  objectName: s1\n  objectType: secretmanager\n  path: a.txt\n- <<: *b\n  path: c.txt\n", []string{"", ""}},
		{"merge key with override", "- &b\n  objectName: s1\n  objectType: secretmanager\n  path: a.txt\n  secretKey: a\n" +
			"- <<: *b\n  path: c.txt\n  secretKey: b\n", []string{"a", "b"}},
		// Whitespace is a key a secret can genuinely hold, so it is a value like
		// any other and the lookup fails later if the secret has no such field.
		{"whitespace secretKey", "- objectName: s1\n  objectType: secretmanager\n  path: a.txt\n  secretKey: \"  \"\n", []string{"  "}},
		// The driver checks the leading ".." on the first element only, so this
		// is accepted there and has to be accepted here.
		{"dotdot name below the root", "- objectName: s1\n  objectType: secretmanager\n  path: d/..data\n", []string{""}},
		{"name at the limit", "- objectName: s1\n  objectType: secretmanager\n  path: " + strings.Repeat("n", maxFileNameLength) + "\n", []string{""}},
		// 17 names of 240 bytes and 16 separators is exactly the driver's limit.
		// Refusing one byte early would block a path the driver writes.
		{"path at the limit", "- objectName: s1\n  objectType: secretmanager\n  path: " +
			strings.TrimSuffix(strings.Repeat(strings.Repeat("d", 240)+"/", 17), "/") + "\n", []string{""}},
		// Sharing a directory is ordinary; only a name used as both is not.
		{"paths sharing a directory", "- objectName: s1\n  objectType: secretmanager\n  path: d/a.txt\n" +
			"- objectName: s2\n  objectType: secretmanager\n  path: d/b.txt\n", []string{"", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfig(mountReq(t, attrib(tc.objects)))
			if err != nil {
				t.Fatalf("expected it to parse: %v", err)
			}
			if len(cfg.ObjectParams) != len(tc.want) {
				t.Fatalf("got %d entries, want %d", len(cfg.ObjectParams), len(tc.want))
			}
			for i, want := range tc.want {
				if cfg.ObjectParams[i].SecretKey != want {
					t.Errorf("objects[%d].secretKey = %q, want %q", i, cfg.ObjectParams[i].SecretKey, want)
				}
			}
		})
	}
}

// The driver sends a hardcoded 0644, so the bound is not about what it asks
// for: it keeps a Mode outside ordinary permission bits from leaving this
// process at all. Both sides of the boundary, because narrowing it would refuse
// modes the driver accepts.
func TestParseConfig_PermissionRange(t *testing.T) {
	attrib, _ := json.Marshal(map[string]string{
		"csi.storage.k8s.io/pod.name":      "p",
		"csi.storage.k8s.io/pod.namespace": "ns",
		"objects":                          "- objectName: s1\n  objectType: secretmanager\n  path: a.txt\n",
	})
	for _, tc := range []struct {
		permission string
		wantErr    bool
	}{
		{"420", false},       // 0644, what the driver actually sends
		{"511", false},       // 0777, the last accepted value
		{"512", true},        // 0o1000, the first refused one
		{"4294967295", true}, // would arrive at the driver as -1
	} {
		req := &v1alpha1.MountRequest{Attributes: string(attrib), Permission: tc.permission}
		_, err := ParseConfig(req)
		if tc.wantErr && err == nil {
			t.Errorf("permission %s: expected it to be refused", tc.permission)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("permission %s: %v", tc.permission, err)
		}
	}
}

// A number that does not fit its target type is quoted whole by the decoder,
// and nothing bounds either field, so neither error may carry what was sent.
func TestParseConfig_DriverFieldsAreNotQuoted(t *testing.T) {
	huge := strings.Repeat("9", 1<<20)
	attrib, _ := json.Marshal(map[string]string{
		"csi.storage.k8s.io/pod.name":      "p",
		"csi.storage.k8s.io/pod.namespace": "ns",
		"objects":                          "- objectName: s1\n  objectType: secretmanager\n  path: a.txt\n",
	})
	for _, tc := range []struct{ attributes, permission, want string }{
		{`{"objects":` + huge + `}`, "420", "volume attributes could not be read"},
		{string(attrib), huge, "file permission could not be read"},
	} {
		_, err := ParseConfig(&v1alpha1.MountRequest{Attributes: tc.attributes, Permission: tc.permission})
		if got := fmt.Sprint(err); got != tc.want {
			t.Errorf("error may only be the fixed message, got %.200q", got)
		}
	}
}

// The shipped SecretProviderClass is the first thing a new user applies, and
// nothing else checks it against the rules this package has grown.
func TestExampleSecretProviderClassParses(t *testing.T) {
	raw, err := os.ReadFile("../../examples/secretproviderclass.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	var spc struct {
		Spec struct {
			Parameters struct {
				Objects string `yaml:"objects"`
			} `yaml:"parameters"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &spc); err != nil {
		t.Fatalf("parse example: %v", err)
	}
	if spc.Spec.Parameters.Objects == "" {
		t.Fatal("example has no objects; this test is reading the wrong field")
	}
	if _, err := ParseConfig(mountReq(t, map[string]string{
		"csi.storage.k8s.io/pod.name":      "p",
		"csi.storage.k8s.io/pod.namespace": "ns",
		"objects":                          spc.Spec.Parameters.Objects,
	})); err != nil {
		t.Fatalf("the shipped example does not pass this package's own validation: %v", err)
	}
}
