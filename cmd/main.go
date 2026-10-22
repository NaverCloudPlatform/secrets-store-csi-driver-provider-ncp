// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"k8s.io/klog/v2"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	"github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/credentials"
	"github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/server"
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	endpoint, credentialPath, apiURL := defineFlags(flag.CommandLine)
	flag.Parse()

	// Flag wins over the credential file, following the usual precedence for
	// configuration sources. Existing deployments pass no flag, so the file
	// value keeps being used.
	resolvedAPIURL := *apiURL
	if resolvedAPIURL == "" {
		resolvedAPIURL = credentials.APIURLFromFile(*credentialPath)
	}
	if resolvedAPIURL == "" {
		klog.ErrorS(nil, "Secret Manager API URL is not configured",
			"flag", "--secretmanager-api-url", "credentialPath", *credentialPath)
		os.Exit(1)
	}
	u, err := parseAPIURL(resolvedAPIURL)
	if err != nil {
		// The URL itself is not logged: it may carry userinfo, and the error
		// already says which rule it broke.
		klog.ErrorS(err, "Secret Manager API URL is not usable",
			"flag", "--secretmanager-api-url", "credentialPath", *credentialPath)
		os.Exit(1)
	}

	// Explicit credential file wins; otherwise fall back to the NKS node's server role.
	creds := credentials.NewChainSource(
		credentials.NewFileProvider(*credentialPath),
		credentials.NewServerRoleProvider(""),
	)
	if _, err := creds.Credentials(context.Background()); err != nil {
		klog.ErrorS(err, "failed to resolve NCP credentials (credential file or NKS server role required)",
			"credentialPath", *credentialPath)
		os.Exit(1)
	}
	klog.InfoS("NCP credentials resolved", "provider", creds.ProviderName())

	klog.InfoS("starting secret-store-csi-driver-provider-ncp", "endpoint", *endpoint)

	// os.Remove already distinguishes "was not there" from a real failure.
	if err := os.Remove(*endpoint); err != nil && !os.IsNotExist(err) {
		klog.ErrorS(err, "failed to remove existing unix socket", "endpoint", *endpoint)
		os.Exit(1)
	}

	listen, err := net.Listen("unix", *endpoint)
	if err != nil {
		klog.ErrorS(err, "failed to listen unix socket", "endpoint", *endpoint)
		os.Exit(1)
	}

	defer func() {
		_ = listen.Close()
		_ = os.Remove(*endpoint)
	}()

	// A unix socket is created 0777 masked by whatever umask the container
	// happens to run with, and connecting to one needs write permission. The
	// usual 0022 already yields this, so on a normal node it changes nothing --
	// it makes the mode a property of this program rather than of the
	// environment, which is what README's security notes rely on.
	if err := os.Chmod(*endpoint, 0o755); err != nil {
		klog.ErrorS(err, "failed to set permissions on the unix socket", "endpoint", *endpoint)
		os.Exit(1)
	}

	// Stated, not inherited: it has to stay above the 128 KiB objects
	// document ParseConfig will accept. This is gRPC's own default.
	grpcServer := grpc.NewServer(grpc.MaxRecvMsgSize(4 << 20))
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)

	providerServer := server.NewServer(u, creds)
	v1alpha1.RegisterCSIDriverProviderServer(grpcServer, providerServer)
	go func() {
		// Serve returns nil once GracefulStop runs; any other error leaves the driver
		// without a provider, so fail the pod rather than idle on the signal wait.
		if err := grpcServer.Serve(listen); err != nil {
			klog.ErrorS(err, "gRPC server terminated unexpectedly")
			klog.Flush()
			os.Exit(1)
		}
	}()

	// initialize health check http server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	health := &http.Server{
		Addr:    ":8080",
		Handler: mux,
		// The pod has no NetworkPolicy, so any pod in the cluster can reach this
		// port. Without a header deadline a connection that sends no headers
		// holds its goroutine open; without an idle deadline one that completed
		// a request and went quiet does the same, because a keep-alive
		// connection gets no read deadline at all when both are unset.
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		// Nothing shuts this server down, so any return at all is a failure --
		// and the liveness probe has nothing to answer either way, so fail the
		// pod here rather than wait for the probe to notice.
		if err := health.ListenAndServe(); err != nil {
			klog.ErrorS(err, "health check server terminated unexpectedly")
			klog.Flush()
			os.Exit(1)
		}
	}()

	sig := <-ch
	klog.InfoS("received signal to terminate", "signal", sig)
	grpcServer.GracefulStop()

}

// defineFlags registers the provider's own flags, apart from klog's. Outside
// main so the deploy manifest's args can be parsed against the same set.
func defineFlags(fs *flag.FlagSet) (endpoint, credentialPath, apiURL *string) {
	endpoint = fs.String("endpoint", "/etc/kubernetes/secrets-store-csi-providers/ncp.sock", "CSI gRPC endpoint")
	credentialPath = fs.String("credential-path", "/credentials/configure", "Credential file for NCP")
	apiURL = fs.String("secretmanager-api-url", "",
		"NCP Secret Manager API URL; takes precedence over secretmanager_api_url in the credential file")
	return endpoint, credentialPath, apiURL
}

// parseAPIURL validates the Secret Manager endpoint. It is separate from main
// so that the rules can be tested: they are a security control, and main() is
// a sequence of os.Exit calls that no test can reach.
//
// No rule quotes the URL back. A rejected URL is exactly the kind that carries
// a credential in its userinfo, and this error is logged.
func parseAPIURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return nil, errors.New("must be an absolute URL")
	case u.User != nil:
		return nil, errors.New("must not carry userinfo")
	case u.Scheme != "https":
		// The signature authenticates a request, it does not encrypt one. Over
		// plain HTTP the access key and the secret value travel in the clear.
		return nil, fmt.Errorf("must use https, not %q", u.Scheme)
	case u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("must be a base URL, with no query or fragment")
	}
	return u, nil
}
