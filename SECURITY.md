# Security Policy

## Supported versions

Fixes go to the most recent release. There is no long-term support branch, and
older tags are not patched — upgrade to the latest release first, then report if
the problem is still there.

## Reporting a vulnerability

Report privately through GitHub, not in a public issue:

**[Open a draft security advisory](https://github.com/NaverCloudPlatform/secrets-store-csi-driver-provider-ncp/security/advisories/new)**
— or use *Security → Advisories → Report a vulnerability* on this repository.

Only the maintainers can see a report filed this way, and it stays private until
a fix is released.

Helpful in a report: the provider version (`kubectl -n kube-system get ds
secrets-store-csi-driver-provider-ncp -o jsonpath='{.spec.template.spec.containers[*].image}'`),
the driver version, and the smallest `SecretProviderClass` that shows the
problem. Please leave real secret values, access keys and cluster identifiers
out of it.

You will get an acknowledgement that the report was received, and an update when
it is triaged. If a fix is needed, the advisory is where it is coordinated and
published.

## Already documented, not a finding

These are known properties of the design, described in the README, and a report
about them will be closed as such:

- **One credential serves the whole cluster.** Any pod that can create a
  `SecretProviderClass` reaches every secret that credential can read; there is
  no per-namespace scoping, and `nodePublishSecretRef` is refused rather than
  honoured. See [Security](README.md#security) and
  [Limitations](README.md#limitations).
- **The provider runs as root.** The gRPC socket lives in a hostPath directory
  kubelet owns as `root:root`, and hostPath ignores `fsGroup`. Everything else
  is dropped. See [Container privileges](README.md#container-privileges).
- **The node server role is readable by every pod on that node**, through the
  instance metadata API. That is a property of the node role, not of this
  provider. See
  [Choosing an authentication method](README.md#choosing-an-authentication-method).

A way to get *past* one of these boundaries — reading a secret the credential
should not reach, escaping the mount directory, or getting a value out of the
provider's logs or events — is a finding, and we want to hear about it.
