// NCP Secrets Store CSI Driver Provider
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/url"

	"k8s.io/klog/v2"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	"github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/credentials"
	"github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/pkg/provider"
)

// Version is set at build time via -ldflags "-X .../pkg/server.Version=<tag>".
var Version = "dev"

type CSIDriverProviderServer struct {
	secretManager *provider.SecretManagerProvider
}

func NewServer(apiURL *url.URL, creds credentials.Source) *CSIDriverProviderServer {
	return &CSIDriverProviderServer{
		secretManager: provider.NewSecretManagerProviderWithCredentials(apiURL, creds),
	}
}

func (s *CSIDriverProviderServer) Version(context.Context, *v1alpha1.VersionRequest) (*v1alpha1.VersionResponse, error) {
	return &v1alpha1.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "secrets-store-csi-driver-provider-ncp",
		RuntimeVersion: Version,
	}, nil
}

func (s *CSIDriverProviderServer) Mount(ctx context.Context, req *v1alpha1.MountRequest) (*v1alpha1.MountResponse, error) {
	config, err := provider.ParseConfig(req)
	if err != nil {
		// The attributes are not logged: the driver puts the pod's ServiceAccount
		// token in them (csi.storage.k8s.io/serviceAccount.tokens) and masks it
		// before logging it itself.
		klog.ErrorS(err, "failed to parse config")
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	values, err := s.secretManager.GetSecretContents(ctx, config.ObjectParams)
	if err != nil {
		klog.ErrorS(err, "failed to get secret content", "pod", config.PodName, "namespace", config.PodNamespace)
		return nil, fmt.Errorf("failed to get secret content: %w", err)
	}

	ov := make([]*v1alpha1.ObjectVersion, 0, len(config.ObjectParams))
	f := make([]*v1alpha1.File, 0, len(config.ObjectParams))
	for i, op := range config.ObjectParams {
		f = append(f, &v1alpha1.File{
			Path:     op.Path,
			Mode:     int32(config.Permission),
			Contents: []byte(values[i]),
		})
		// The driver folds these into a map keyed by Id, so the Id has to be
		// unique within the mount. objectType/objectName is not: one secret
		// mounted to two paths would collapse into a single entry.
		ov = append(ov, &v1alpha1.ObjectVersion{
			Id:      op.Path,
			Version: "1",
		})
	}
	// The driver writes the files after this returns, and can still refuse the
	// response -- over its --max-call-recv-msg-size it does, with every secret
	// already fetched. Nothing here knows whether anything was mounted, so this
	// says what this process did rather than what it hopes came of it.
	klog.InfoS("returning secrets", "files", len(f), "pod", config.PodName, "namespace", config.PodNamespace)

	return &v1alpha1.MountResponse{
		ObjectVersion: ov,
		Files:         f,
	}, nil
}
