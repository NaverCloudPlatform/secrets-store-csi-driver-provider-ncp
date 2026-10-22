// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"

	credentials "github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/credentials"
	hmac "github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/hmac"
)

const defaultAPITimeout = 30 * time.Second

const (
	// maxResponseBytes bounds a Secret Manager response. Secret values are
	// small, and this is the only cap on one: a mount holds every value it
	// fetched at once, so what an oversized response runs into is the pod's
	// memory limit, and that kills the provider for the whole node.
	maxResponseBytes = 4 << 20
	// maxErrorBodyBytes is how much of a failed response gets quoted back.
	maxErrorBodyBytes = 1 << 10
)

// maxSecretListPages bounds the name->id lookup. Termination already keys off
// our own page counter, but a response claiming an implausible totalPageNo
// should fail fast rather than be walked to the end.
const maxSecretListPages = 500

type SecretManagerProvider struct {
	creds      credentials.Source
	base       string // scheme://host, what a request is addressed to
	basePath   string // API path prefix, what a signature covers
	httpClient *http.Client
}

// NewSecretManagerProvider builds a provider backed by fixed keys.
func NewSecretManagerProvider(accessKey, secretKey string, apiURL *url.URL) *SecretManagerProvider {
	return NewSecretManagerProviderWithCredentials(apiURL, credentials.NewStaticSource(accessKey, secretKey))
}

// NewSecretManagerProviderWithCredentials builds a provider that resolves
// credentials from creds on every request. Taking a parsed URL keeps the
// validation in one place -- cmd/main.go -- so there is no failure to report
// here and no way to end up with a half-built provider.
func NewSecretManagerProviderWithCredentials(apiURL *url.URL, creds credentials.Source) *SecretManagerProvider {
	return &SecretManagerProvider{
		creds:    creds,
		base:     apiURL.Scheme + "://" + apiURL.Host,
		basePath: strings.TrimSuffix(apiURL.Path, "/"),
		httpClient: &http.Client{
			Timeout:   defaultAPITimeout,
			Transport: apiTransport(),
			// A redirect would resend the signed headers to a URI the signature
			// does not cover, at a host that was never validated.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirect not followed")
			},
		},
	}
}

// maxIdleConnsPerHost is what the pool keeps for the one host this talks to.
// The default is two. Requests within one mount are sequential and reuse a
// connection at that default; what does not is a burst of concurrent mounts,
// which is what rotation produces -- one per pod on the node, each paying for a
// fresh TLS handshake past the second.
const maxIdleConnsPerHost = 100

// apiTransport is the standard transport with a pool that fits this workload.
// Cloned rather than built, to keep the dial and handshake timeouts that come
// with it.
func apiTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = maxIdleConnsPerHost
	return t
}

// get signs an NCP API Gateway request (signature v2) and decodes the JSON response into out.
// path is the API path with optional query, e.g. "/secrets?pageNo=1".
func (sm *SecretManagerProvider) get(ctx context.Context, path string, out interface{}) error {
	cred, err := sm.creds.Credentials(ctx)
	if err != nil {
		return fmt.Errorf("resolve credentials: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sm.base+sm.basePath+path, nil)
	if err != nil {
		return err
	}

	// Sign what is actually sent: RequestURI is the escaped path and query the
	// request carries, so the signature cannot drift from the URL.
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)
	signature := hmac.Sign(cred.SecretKey, req.Method, req.URL.RequestURI(), cred.AccessKey, timestamp)

	req.Header.Set("x-ncp-apigw-timestamp", timestamp)
	req.Header.Set("x-ncp-iam-access-key", cred.AccessKey)
	req.Header.Set("x-ncp-apigw-signature-v2", signature)

	resp, err := sm.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Quote what the API said. Without it a bad key, a missing Sub Account
		// policy and a clock skew all read as "unexpected status 401". Error
		// responses only: a successful /values body carries the secret itself.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		// Drain the remainder so the connection stays reusable while the API
		// keeps failing.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	// A 200 body is the secret itself, and the decoder quotes the byte it
	// stopped on. Same rule as extractJSONValue: say what is wrong without
	// saying what was read. The caller names which call it was.
	//
	// Only syntax and type errors quote the body. The decoder reads from the
	// connection as it goes, so a reset, a timeout or the size cap also surface
	// here; they carry nothing of the body and are the actual cause, so they
	// are not reported as a bad response. That holds while nothing decoded here
	// uses a ",string" tag, json.Number or DisallowUnknownFields: each quotes
	// input in an error of its own type, which would pass straight through.
	// Go 1.27 changed the encoding/json implementation, so re-check under it.
	body := &io.LimitedReader{R: resp.Body, N: maxResponseBytes}
	if err := json.NewDecoder(body).Decode(out); err != nil {
		var syntaxErr *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		switch {
		case body.N == 0:
			return fmt.Errorf("response reached the %d-byte limit", maxResponseBytes)
		case errors.As(err, &syntaxErr), errors.As(err, &typeErr):
			return errors.New("response is not valid JSON")
		}
		return fmt.Errorf("reading response: %w", err)
	}
	return nil
}

type secretListResp struct {
	Data *struct {
		CurrentPageNo int `json:"currentPageNo"`
		TotalPageNo   int `json:"totalPageNo"`
		SecretList    []struct {
			SecretID   string `json:"secretId"`
			SecretName string `json:"secretName"`
		} `json:"secretList"`
	} `json:"data"`
}

type secretValuesResp struct {
	Data *struct {
		DecryptedSecretChain *struct {
			// Pointer so an absent ACTIVE value is a failure rather than an
			// empty secret mounted without complaint.
			Active *string `json:"active"`
		} `json:"decryptedSecretChain"`
	} `json:"data"`
}

// GetSecretContents resolves one value per entry in ops, in order. A secret
// named by more than one entry is fetched once: the shipped example mounts the
// same secret twice, and every entry used to repeat the whole name lookup and
// value fetch.
func (sm *SecretManagerProvider) GetSecretContents(ctx context.Context, ops []*ObjectParam) ([]string, error) {
	fetched := make(map[string]string, len(ops))
	out := make([]string, len(ops))

	for i, op := range ops {
		value, ok := fetched[op.ObjectName]
		if !ok {
			var err error
			if value, err = sm.getSecretValue(ctx, op.ObjectName); err != nil {
				return nil, err
			}
			fetched[op.ObjectName] = value
		}
		if op.SecretKey == "" {
			out[i] = value
			continue
		}
		extracted, err := extractJSONValue(value, op.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to extract secretKey[%s] from secret[%s]: %w", clip(op.SecretKey), op.ObjectName, err)
		}
		out[i] = extracted
	}
	return out, nil
}

// GetSecretContent resolves a single object.
func (sm *SecretManagerProvider) GetSecretContent(ctx context.Context, op ObjectParam) (string, error) {
	out, err := sm.GetSecretContents(ctx, []*ObjectParam{&op})
	if err != nil {
		return "", err
	}
	return out[0], nil
}

// getSecretValue returns the ACTIVE value of the named secret.
func (sm *SecretManagerProvider) getSecretValue(ctx context.Context, name string) (string, error) {
	secretId, err := sm.findSecretIdByName(ctx, name)
	if err != nil {
		return "", err
	}

	// From here name has matched a secret the API listed, so it is bounded by
	// what the API accepts as a name and is quoted unclipped.
	var r secretValuesResp
	if err := sm.get(ctx, "/secrets/"+url.PathEscape(secretId)+"/values", &r); err != nil {
		return "", fmt.Errorf("failed to get secret[%s] values: %w", name, err)
	}
	if r.Data == nil || r.Data.DecryptedSecretChain == nil {
		return "", fmt.Errorf("secret[%s] values response missing decryptedSecretChain", name)
	}
	if r.Data.DecryptedSecretChain.Active == nil {
		return "", fmt.Errorf("secret[%s] values response has no active value", name)
	}

	klog.V(4).InfoS("got secret from SecretManager", "secretName", name, "secretID", secretId)
	return *r.Data.DecryptedSecretChain.Active, nil
}

func (sm *SecretManagerProvider) findSecretIdByName(ctx context.Context, secretName string) (string, error) {
	for pageNo := 1; ; pageNo++ {
		var r secretListResp
		if err := sm.get(ctx, fmt.Sprintf("/secrets?pageNo=%d", pageNo), &r); err != nil {
			return "", fmt.Errorf("failed to get secret[%s]: %w", clip(secretName), err)
		}
		if r.Data == nil {
			return "", fmt.Errorf("secret list response missing data (page %d)", pageNo)
		}

		for _, secret := range r.Data.SecretList {
			if secret.SecretName == secretName {
				return secret.SecretID, nil
			}
		}

		// Terminate on our own counter. Keying off the server-reported
		// currentPageNo lets a response that never advances loop forever.
		if pageNo >= r.Data.TotalPageNo {
			break
		}
		if pageNo >= maxSecretListPages {
			return "", fmt.Errorf("secret list exceeded %d pages looking for secret[%s]", maxSecretListPages, clip(secretName))
		}
	}

	return "", fmt.Errorf("failed to find secret[%s]", clip(secretName))
}

// extractJSONValue extracts the value of the given key from a JSON secret string.
// Values are taken as raw JSON rather than decoded into interface{}: decoding
// routed every number through float64, which rounded fractions to integers and
// lost precision beyond 2^53, and re-encoding objects reordered their keys.
func extractJSONValue(jsonStr, key string) (string, error) {
	var jsonMap map[string]json.RawMessage
	// A JSON null decodes into a nil map without error, so it is checked rather
	// than left to report a key that was never going to be there.
	if err := json.Unmarshal([]byte(jsonStr), &jsonMap); err != nil || jsonMap == nil {
		// The decoder quotes the byte it stopped on, and that byte is the
		// secret's. This error reaches the provider log and the pod event, so
		// it says what is wrong without saying what was read.
		return "", errors.New("secret is not a JSON object")
	}

	raw, exists := jsonMap[key]
	if !exists {
		return "", fmt.Errorf("key '%s' not found in JSON", clip(key))
	}

	// Strings are unquoted. Everything else -- numbers, bools, objects, arrays,
	// null -- is mounted as its original JSON text. The pointer target keeps a
	// JSON null from decoding into an empty string.
	var str *string
	if err := json.Unmarshal(raw, &str); err == nil && str != nil {
		return *str, nil
	}
	return string(raw), nil
}
