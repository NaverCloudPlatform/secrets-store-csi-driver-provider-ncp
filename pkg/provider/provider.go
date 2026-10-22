// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"go.yaml.in/yaml/v2"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

type Config struct {
	PodName      string
	PodNamespace string
	ObjectParams []*ObjectParam
	Permission   os.FileMode
}
type ObjectParam struct {
	// secretmanager
	ObjectType string `json:"objectType" yaml:"objectType"`

	// secretName registered in Secret Manager
	ObjectName string `json:"objectName" yaml:"objectName"`

	// Path of mounted file
	Path string `json:"path" yaml:"path"`

	// key to extract from the JSON secret (optional)
	SecretKey string `json:"secretKey,omitempty" yaml:"secretKey,omitempty"`
}

// maxObjectsPerMount is a backstop against an absurd payload, not a budget.
// Distinct secrets are what cost remote calls -- entries naming a secret that
// was already fetched only cost a local JSON read -- and real deployments run
// to about a hundred entries against a single secret, one per secretKey, which
// is the shape the NCP guide itself demonstrates.
const maxObjectsPerMount = 1000

// maxObjectsBytes bounds the objects document before it is parsed, because
// parsing is what costs memory and the document comes from whoever wrote the
// SecretProviderClass. Sized on the densest shape a byte can buy, not a
// realistic one: yaml's cost follows node count, and a flow sequence of
// one-letter scalars buys many more nodes per byte than an entry does, plus
// one decoder error line each. At 1 MiB that shape's heap alone exceeded
// 200 MiB, and its RSS 300 MiB against a 128Mi pod limit; the per-element
// errors, and the copies made as the provider logs them and hands them back to
// the driver, were over half of that heap. That is per parse; nothing bounds
// how many run at once. Past an average entry of about 131 bytes this binds
// before the entry cap above, and it bounds the parse alone: the secrets
// fetched for one mount, and the response built from them, have no combined
// cap.
const maxObjectsBytes = 128 << 10

// maxParseErrorBytes bounds what a failed parse sends outward. yaml names every
// element it could not decode, one line each, so a document inside the size cap
// still yields megabytes: 128 KiB of flow-style scalars gives 65,536 lines and
// 3.94 MiB. That string is logged here, returned as the gRPC status, logged
// again by the driver, and repeated on every kubelet retry. Matches the 1 KiB
// this package already quotes a failed API response back at.
//
// This does not make the parse cheaper -- yaml collects the whole list inside
// Decode, so the peak is past by the time this runs, which is why the size cap
// is what bounds the parse. This bounds what leaves the process.
const maxParseErrorBytes = 1 << 10

// trimParseError cuts a parse failure down to its first complaints, which are
// the ones read, and says how many it dropped.
func trimParseError(err error) error {
	msg := err.Error()
	if len(msg) <= maxParseErrorBytes {
		return err
	}
	kept := msg[:maxParseErrorBytes]
	// Cut on a line, so the last thing shown is a whole complaint.
	if i := strings.LastIndexByte(kept, '\n'); i > 0 {
		kept = kept[:i]
		return fmt.Errorf("%s\n... and %d more lines", kept, strings.Count(msg[len(kept):], "\n"))
	}
	// No line boundary in the first maxParseErrorBytes. yaml.v2 always breaks
	// its first line, so nothing reaches this today, but the parameter is an
	// error and the next caller need not be yaml. Counting lines here would
	// report "0 more" while dropping most of the message, and the cut can land
	// inside a rune, since yaml quotes fragments of the document.
	return fmt.Errorf("%s... (truncated)", strings.ToValidUTF8(kept, ""))
}

// maxQuotedBytes bounds each SecretProviderClass field an error quotes back.
// Nothing else bounds objectType, objectName or secretKey, and a path is
// quoted before its own length is checked, so any of them can be most of the
// 128 KiB document -- and an error goes out as often as a parse failure does.
// A checked path is still 4 KiB, so every quote of one is clipped too. Longer
// than any name the driver or the API accepts.
const maxQuotedBytes = 256

// clip returns s for quoting in an error, cut to maxQuotedBytes.
func clip(s string) string {
	if len(s) <= maxQuotedBytes {
		return s
	}
	return fmt.Sprintf("%s... (%d bytes)", strings.ToValidUTF8(s[:maxQuotedBytes], ""), len(s))
}

// The driver applies these to every path when it writes, which is after this
// provider has fetched every secret. Mirrored from
// sigs.k8s.io/secrets-store-csi-driver/pkg/util/fileutil so that a path it will
// refuse costs nothing to find out.
const (
	maxPathLength     = 4096
	maxFileNameLength = 255
)

const (
	objectTypeSecretManager = "secretmanager"
	attribKeyObjects        = "objects"
	attribKeyPodName        = "csi.storage.k8s.io/pod.name"
	attribKeyPodNamespace   = "csi.storage.k8s.io/pod.namespace"
)

// checkNoPerPodSecrets refuses a nodePublishSecretRef, which the driver
// forwards in MountRequest.Secrets. This provider signs every request with one
// cluster-wide credential and has never read that field, so a pod carrying a
// ref mounts on the shared key and reads as scoped when it is not -- a refusal
// is the only way that stops being invisible.
//
// Refused on the keys a ref can carry, not on the field being non-empty. A
// Secret's data keys match [-._a-zA-Z0-9]+ (apiserver, IsConfigMapKey), so a
// key holding a "/" did not come from one -- kubelet put it there. Kubelet
// does: where the CSIDriver sets serviceAccountTokenInSecrets it delivers the
// pod's service account tokens under csi.storage.k8s.io/serviceAccount.tokens,
// and the driver forwards that map unchanged. Refusing a non-empty field would
// break every mount on such a cluster; naming that one key would break again
// on the next reserved key, which is how this rule got here.
//
// An absent ref arrives as "null" where the driver marshals a nil map, and as
// "{}" where it builds an empty one. Both mean no ref -- and "{}" is also what
// a ref to a Secret with no keys sends, which passes for the same reason: it
// carries no credential, so there is nothing for it to scope.
//
// Nothing of the field is quoted. It holds the referenced Secret's data, and
// this error reaches the provider log and the pod's events.
func checkNoPerPodSecrets(raw string) error {
	if raw == "" {
		return nil
	}
	var secrets map[string]string
	if err := json.Unmarshal([]byte(raw), &secrets); err != nil {
		return errors.New("nodePublishSecretRef could not be read")
	}
	for key := range secrets {
		if !strings.Contains(key, "/") {
			return errors.New("nodePublishSecretRef is set, but this provider signs every request with one cluster-wide credential")
		}
	}
	return nil
}

func ParseConfig(req *v1alpha1.MountRequest) (*Config, error) {
	var attrib map[string]string
	var permission os.FileMode

	if err := checkNoPerPodSecrets(req.GetSecrets()); err != nil {
		return nil, err
	}

	// Both come from the driver, and neither error is quoted back: a number
	// that does not fit the target type is quoted whole, and nothing bounds it.
	err := json.Unmarshal([]byte(req.GetAttributes()), &attrib)
	if err != nil {
		return nil, errors.New("volume attributes could not be read")
	}

	err = json.Unmarshal([]byte(req.GetPermission()), &permission)
	if err != nil {
		return nil, errors.New("file permission could not be read")
	}
	// Mount hands the driver an int32, and the provider protocol has no use for
	// anything but ordinary permission bits. The driver sends a hardcoded 0644
	// rather than the pod's defaultMode, so nothing reaches this on the normal
	// path and no exploit of it is known; it keeps a Mode outside that range
	// from leaving this process at all.
	if permission > 0o777 {
		return nil, fmt.Errorf("permission %#o is out of range", uint32(permission))
	}

	podName, exists := attrib[attribKeyPodName]
	if !exists {
		return nil, fmt.Errorf("failed to get pod name")
	}

	podNamespace, exists := attrib[attribKeyPodNamespace]
	if !exists {
		return nil, fmt.Errorf("failed to get pod namespace")
	}

	objectString, exists := attrib[attribKeyObjects]
	if !exists {
		return nil, fmt.Errorf("objects must be set")
	}

	// Checked on the raw document: refusing it after the parse would be
	// refusing it after the cost has already been paid.
	if len(objectString) > maxObjectsBytes {
		return nil, fmt.Errorf("objects is %d bytes, at most %d are allowed", len(objectString), maxObjectsBytes)
	}

	var objects []*ObjectParam
	// Strict, so an unknown or duplicated field is rejected instead of ignored.
	// A silent typo changes what gets mounted: "secretKye" leaves SecretKey
	// empty, which mounts the whole secret where one value was asked for.
	dec := yaml.NewDecoder(strings.NewReader(objectString))
	dec.SetStrict(true)
	if err := dec.Decode(&objects); err != nil && !errors.Is(err, io.EOF) {
		// The raw document is left out: it is attacker-controlled, it is copied
		// into both the error and the driver event, and it lists every secret
		// name in it. The entry checks below quote only the failing entry's own
		// fields, clipped.
		return nil, fmt.Errorf("failed to parse objects: %w", trimParseError(err))
	}
	// yaml reads one document from a stream and discards whatever follows, so a
	// "---" used to drop every entry after it -- no error, no event, and a pod
	// that starts with files missing. Any second document is refused, including
	// an empty one from a trailing separator: allowing that and returning would
	// go back to discarding a third document's entries, and walking the whole
	// stream to prove they are all empty is a loop over attacker-controlled
	// input for a spelling nothing needs.
	if err := dec.Decode(new(interface{})); !errors.Is(err, io.EOF) {
		return nil, errors.New("objects must be a single YAML document")
	}
	if len(objects) == 0 {
		return nil, fmt.Errorf("objects must list at least one entry")
	}
	if len(objects) > maxObjectsPerMount {
		return nil, fmt.Errorf("objects lists %d entries, at most %d are allowed", len(objects), maxObjectsPerMount)
	}

	// Decoded again as maps, because a struct field cannot tell a secretKey
	// that was written with no value from one that was absent -- yaml gives
	// both the same empty string -- while a map keeps the key either way.
	// Not strictly: strict counts a merge key's fields as already set, so
	// overriding one (`<<: *base` and then `path:`) reads as a duplicate on a
	// map though the struct decode above accepts it. Both decodes see the same
	// sequence, and yaml only drops an element along with an error, so past
	// this point the two have the same length and index together.
	var written []map[string]interface{}
	if err := yaml.Unmarshal([]byte(objectString), &written); err != nil {
		return nil, fmt.Errorf("failed to parse objects: %w", trimParseError(err))
	}

	// Argued above rather than enforced, and enforced anyway: being wrong here
	// is an index panic in the loop below, which gRPC does not recover, and
	// that takes the provider down for every pod on the node.
	if len(written) != len(objects) {
		return nil, errors.New("objects did not decode consistently")
	}

	for i, o := range objects {
		// An empty list entry decodes to nil. Reading through it would panic,
		// and gRPC does not recover handler panics, so one bad
		// SecretProviderClass would take down the provider for the whole node.
		if o == nil {
			return nil, fmt.Errorf("objects[%d] is empty", i)
		}
		if o.ObjectType != objectTypeSecretManager {
			return nil, fmt.Errorf("objects[%d]: invalid objectType[%s]", i, clip(o.ObjectType))
		}
		if o.ObjectName == "" || o.Path == "" {
			return nil, fmt.Errorf("objects[%d]: objectName[%s] and path[%s] must be set for objectType[%s]", i, clip(o.ObjectName), clip(o.Path), o.ObjectType)
		}
		// Mounting the whole secret is the wrong answer for a secretKey the
		// author wrote and left empty -- which is what a template renders when
		// its value is unset.
		if v, set := written[i]["secretKey"]; set && (v == nil || v == "") {
			return nil, fmt.Errorf("objects[%d]: secretKey is set but has no value; omit it to mount the whole secret", i)
		}
		// Checked here, before any secret is fetched. The driver rejects an
		// escaping path when it writes, but by then the value has been read out
		// of Secret Manager and logged as an access.
		if c := path.Clean(o.Path); c != o.Path || c == "." || c == ".." ||
			path.IsAbs(c) || strings.HasPrefix(c, "../") {
			return nil, fmt.Errorf("objects[%d]: path[%s] must be a clean relative path", i, clip(o.Path))
		}
		if len(o.Path) > maxPathLength {
			return nil, fmt.Errorf("objects[%d]: path is %d bytes, at most %d are allowed", i, len(o.Path), maxPathLength)
		}
		names := strings.Split(o.Path, "/")
		for _, name := range names {
			if len(name) > maxFileNameLength {
				return nil, fmt.Errorf("objects[%d]: path[%s] has a name longer than %d bytes", i, clip(o.Path), maxFileNameLength)
			}
		}
		// Only the first element, as the driver has it: "..data" and
		// "..2026_09_16..." are the names the atomic writer keeps for itself in
		// the mount directory. Deeper in, they are ordinary names.
		if strings.HasPrefix(names[0], "..") && len(names[0]) > 2 {
			return nil, fmt.Errorf("objects[%d]: path[%s] must not start with '..'", i, clip(o.Path))
		}
		// Against the entries already checked, in order. A repeated path drops
		// one entry without a word, and a name used as both a file and a
		// directory fails the whole mount on whichever the driver reaches
		// second -- both only after every secret has been fetched.
		for j := 0; j < i; j++ {
			switch prev := objects[j].Path; {
			case prev == o.Path:
				return nil, fmt.Errorf("objects[%d]: path[%s] is already used by objects[%d]", i, clip(o.Path), j)
			case isUnder(o.Path, prev):
				return nil, fmt.Errorf("objects[%d]: path[%s] is under path[%s], a file in objects[%d]", i, clip(o.Path), clip(prev), j)
			case isUnder(prev, o.Path):
				return nil, fmt.Errorf("objects[%d]: path[%s] is a directory in objects[%d]", i, clip(o.Path), j)
			}
		}
	}

	return &Config{
		PodName:      podName,
		PodNamespace: podNamespace,
		ObjectParams: objects,
		Permission:   permission,
	}, nil
}

// isUnder reports whether p names something inside dir, comparing whole
// elements so that "ab" is not under "a". Walking up from a path with path.Dir
// instead built every ancestor of every entry and kept them: a path may be 4096
// bytes and 2048 elements deep, and a document of those cost more after the
// parse than the parse the byte cap above was there to bound.
func isUnder(p, dir string) bool {
	return len(p) > len(dir) && p[len(dir)] == '/' && p[:len(dir)] == dir
}
