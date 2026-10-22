// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

// Package credentials resolves NCP API credentials from the credential file
// mounted into the pod or from the NKS node's server role.
package credentials

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/ini.v1"
)

// Value is one set of API credentials. A zero Expiration means non-expiring.
type Value struct {
	AccessKey  string
	SecretKey  string
	Expiration time.Time
}

func (v Value) valid() bool {
	return v.AccessKey != "" && v.SecretKey != ""
}

// Provider retrieves credentials from a single source. The context bounds any
// network call the retrieval makes.
type Provider interface {
	Name() string
	Retrieve(ctx context.Context) (Value, error)
}

// Source yields signing credentials at request time.
type Source interface {
	Credentials(ctx context.Context) (Value, error)
}

const (
	keyAccessKey = "ncloud_access_key_id"
	keySecretKey = "ncloud_secret_access_key"
	keyAPIURL    = "secretmanager_api_url"
)

// FileProvider reads credentials from the ini file mounted into the pod.
type FileProvider struct {
	path string
}

// NewFileProvider returns a Provider that reads credentials from path.
func NewFileProvider(path string) *FileProvider {
	return &FileProvider{path: path}
}

func (p *FileProvider) Name() string { return "FileProvider" }

// Retrieve reads the file. The context is unused: no network call is made.
func (p *FileProvider) Retrieve(context.Context) (Value, error) {
	cfg, err := ini.Load(p.path)
	if err != nil {
		// go-ini quotes the line it stopped on, and that line is most likely
		// the one holding the secret key. Both sources failing is what puts the
		// pod in CrashLoopBackOff, so this error is read straight off
		// kubectl logs -- it says what is wrong without saying what was read.
		if errors.Is(err, fs.ErrNotExist) {
			// The file is absent by design under the server role, and this
			// error is read next to that provider's own.
			return Value{}, fmt.Errorf("credential file %s does not exist", p.path)
		}
		return Value{}, fmt.Errorf("credential file %s could not be read or is not valid ini", p.path)
	}
	section := cfg.Section("")
	access := section.Key(keyAccessKey).String()
	secret := section.Key(keySecretKey).String()
	if access == "" || secret == "" {
		return Value{}, fmt.Errorf("credential file %s: %s and %s must be set", p.path, keyAccessKey, keySecretKey)
	}
	return Value{AccessKey: access, SecretKey: secret}, nil
}

// APIURLFromFile returns secretmanager_api_url from the credential file.
// A missing file, a malformed file, or an absent key yields an empty string
// so the caller can fall back to its flag.
func APIURLFromFile(path string) string {
	cfg, err := ini.Load(path)
	if err != nil {
		return ""
	}
	return cfg.Section("").Key(keyAPIURL).String()
}

const (
	defaultMetadataEndpoint = "http://169.254.169.254"
	metadataCredsPath       = "/latest/meta-data/iam/security-credentials/"
	metadataTokenPath       = "/latest/api/token"
	metadataTokenHeader     = "X-NCP-METADATA-TOKEN"
	metadataTokenTTLHeader  = "X-NCP-METADATA-TOKEN-TTL-SECONDS"
	// metadataTokenTTLSeconds is deliberately short. The token is issued and
	// spent within one Retrieve, a few milliseconds apart, so a long-lived
	// session would only widen the window in which a leaked token is useful.
	// NCP accepts 1 to 21600.
	metadataTokenTTLSeconds = 60
	metadataTimeout         = 3 * time.Second
	metadataBodyLimit       = 1 << 20
)

// ServerRoleProvider fetches temporary credentials issued to the NKS node's
// server role through the instance metadata API.
type ServerRoleProvider struct {
	endpoint   string
	httpClient *http.Client
}

// NewServerRoleProvider falls back to the well-known metadata endpoint when
// endpoint is empty. Tests pass an httptest URL.
func NewServerRoleProvider(endpoint string) *ServerRoleProvider {
	if endpoint == "" {
		endpoint = defaultMetadataEndpoint
	}
	return &ServerRoleProvider{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: metadataTimeout,
			// The instance metadata endpoint is link-local and must never be
			// routed through a proxy, even when HTTP_PROXY/HTTPS_PROXY is set
			// in the pod's environment (common on NCP public-sector/enterprise
			// clusters).
			Transport: &http.Transport{Proxy: nil},
			// A redirect would carry the session token off the link-local
			// endpoint.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirect not followed")
			},
		},
	}
}

func (p *ServerRoleProvider) Name() string { return "ServerRoleProvider" }

func (p *ServerRoleProvider) Retrieve(ctx context.Context) (Value, error) {
	token, err := p.issueToken(ctx)
	if err != nil {
		return Value{}, fmt.Errorf("issue metadata token: %w", err)
	}

	list, err := p.get(ctx, metadataCredsPath, token)
	if err != nil {
		return Value{}, fmt.Errorf("list server roles: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(list))
	if !scanner.Scan() || strings.TrimSpace(scanner.Text()) == "" {
		return Value{}, errors.New("no server role attached")
	}
	roleID := strings.TrimSpace(scanner.Text())

	body, err := p.get(ctx, metadataCredsPath+url.PathEscape(roleID), token)
	if err != nil {
		return Value{}, fmt.Errorf("get server role credentials: %w", err)
	}
	var resp struct {
		AccessKeyID     string    `json:"AccessKeyId"`
		SecretAccessKey string    `json:"SecretAccessKey"`
		Expiration      time.Time `json:"Expiration"`
		Code            string    `json:"Code"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		// A 200 body here is the credential document itself, and the decoder
		// quotes the byte it stopped on. Same rule the credential file and the
		// Secret Manager response already follow.
		return Value{}, errors.New("server role credentials are not valid JSON")
	}
	if resp.Code != "" && resp.Code != "Success" {
		return Value{}, fmt.Errorf("server role credentials: code %s", resp.Code)
	}
	// These credentials are temporary; without an expiration the cache would
	// never refresh them.
	if resp.Expiration.IsZero() {
		return Value{}, errors.New("server role credentials missing expiration")
	}
	// An already-expired value would cache as immediately "expiring", trigger
	// an immediate refresh that returns the same expired value, and loop.
	if resp.Expiration.Before(time.Now()) {
		return Value{}, errors.New("server role credentials already expired")
	}
	return Value{
		AccessKey:  resp.AccessKeyID,
		SecretKey:  resp.SecretAccessKey,
		Expiration: resp.Expiration,
	}, nil
}

// issueToken opens a metadata v2 session. Metadata v2 is used unconditionally:
// NCP documents v1 as exposed to SSRF -- any request-forgery bug in a pod on
// this node could read the node's role credentials through it -- and an
// instance that still allows v1 accepts v2 requests just the same, so there is
// nothing to fall back to and nothing to negotiate.
func (p *ServerRoleProvider) issueToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.endpoint+metadataTokenPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(metadataTokenTTLHeader, strconv.Itoa(metadataTokenTTLSeconds))

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, metadataBodyLimit))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata API returned HTTP %d: %s", resp.StatusCode, errorDetail(body))
	}
	// A failed issue can still answer 200 with an error message in the body,
	// which would then be sent as a token and rejected further along.
	token := strings.TrimSpace(string(body))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("metadata API did not return a token")
	}
	return token, nil
}

func (p *ServerRoleProvider) get(ctx context.Context, path, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(metadataTokenHeader, token)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, metadataBodyLimit))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata API returned HTTP %d: %s", resp.StatusCode, errorDetail(body))
	}
	return string(body), nil
}

// errorDetail quotes what the metadata API said about a failure. Without it a
// role that is not attached, a policy that is missing and a token that expired
// all read as "returned HTTP 401". Failures only: a successful body is the
// credential itself. The body is already bounded; this bounds the message.
func errorDetail(body []byte) string {
	const limit = 1 << 10
	if len(body) > limit {
		body = body[:limit]
	}
	return strings.TrimSpace(string(body))
}

// refreshMargin is how long before expiry the chain proactively refreshes.
const refreshMargin = 10 * time.Minute

// StaticSource serves fixed keys supplied by the caller.
type StaticSource struct {
	value Value
}

// NewStaticSource returns a Source that always serves accessKey/secretKey.
func NewStaticSource(accessKey, secretKey string) *StaticSource {
	return &StaticSource{value: Value{AccessKey: accessKey, SecretKey: secretKey}}
}

// Credentials returns the fixed access/secret key pair, or an error if either
// is empty.
func (s *StaticSource) Credentials(context.Context) (Value, error) {
	if !s.value.valid() {
		return Value{}, errors.New("static credentials are empty")
	}
	return s.value, nil
}

// ChainSource caches the first provider that yields credentials and refreshes
// expiring values ahead of time, keeping the last good value if a refresh
// attempt fails while that value is still valid.
type ChainSource struct {
	mu        sync.Mutex
	providers []Provider
	current   Value
	provider  string
	now       func() time.Time
}

// NewChainSource returns a Source that tries providers in order, caching the
// first one that succeeds.
func NewChainSource(providers ...Provider) *ChainSource {
	return &ChainSource{providers: providers, now: time.Now}
}

// ProviderName reports which provider served the current credentials.
func (s *ChainSource) ProviderName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.provider
}

// Credentials returns a cached value, refreshing it ahead of expiry. If a
// refresh attempt fails, it keeps serving the last good value until that
// value truly expires, only then returning an error.
func (s *ChainSource) Credentials(ctx context.Context) (Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.current.valid() && !s.expiring(s.current) {
		return s.current, nil
	}

	var errs []error
	for _, p := range s.providers {
		v, err := p.Retrieve(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
			continue
		}
		if !v.valid() {
			errs = append(errs, fmt.Errorf("%s: empty credentials", p.Name()))
			continue
		}
		s.current = v
		s.provider = p.Name()
		return v, nil
	}

	// Refresh failed: the cached value stays usable until it actually expires.
	if s.current.valid() && !s.expired(s.current) {
		return s.current, nil
	}
	return Value{}, fmt.Errorf("no usable credentials: %w", errors.Join(errs...))
}

func (s *ChainSource) expiring(v Value) bool {
	return !v.Expiration.IsZero() && s.now().After(v.Expiration.Add(-refreshMargin))
}

func (s *ChainSource) expired(v Value) bool {
	return !v.Expiration.IsZero() && s.now().After(v.Expiration)
}
