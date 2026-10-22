# NCP Secrets Store CSI Driver Provider

A provider for the [Kubernetes Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)
that mounts secrets from [Naver Cloud Platform (NCP) Secret Manager](https://www.ncloud.com/)
into Kubernetes pods as files.

> **Community / out-of-tree provider.** This provider is developed and maintained
> in this repository. It is not part of the
> [kubernetes-sigs/secrets-store-csi-driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver)
> project, and issues or pull requests are handled here.

## Overview

The Secrets Store CSI Driver delegates to provider plugins to fetch secrets from
an external store. This provider connects the driver to NCP Secret Manager: when a
pod requests a volume, the driver calls this provider over a gRPC unix socket, and
the provider retrieves the secrets and returns them to be mounted into the pod.

```
kubelet → Secrets Store CSI Driver → (gRPC/unix socket) → ncp provider → NCP Secret Manager API
```

## Compatibility

This provider implements the Secrets Store CSI Driver provider protocol
`v1alpha1`. Choose a driver release that supports your Kubernetes version
according to the [upstream documentation](https://secrets-store-csi-driver.sigs.k8s.io/).

The current release has been verified with:

| Component | Verified version |
|---|---|
| Secrets Store CSI Driver | v1.6.0 (Helm chart 1.6.0) |
| Provider protocol | `v1alpha1` |
| Kubernetes | v1.36.2 (NKS) |

## Requirements

- A Kubernetes cluster with the [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/getting-started/installation.html) installed
- NCP Secret Manager enabled
- An NCP API key (Access Key / Secret Key), or a Server-type Sub Account role attached to the node pool as an alternative

## Installation

### 1. Install the Secrets Store CSI Driver

```bash
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install -n kube-system csi-secrets-store \
  secrets-store-csi-driver/secrets-store-csi-driver --version 1.6.0
```

The version is pinned to the chart this provider was verified against — see
[Compatibility](#compatibility).

### 2. Provide NCP credentials

The provider resolves credentials in this order: the mounted credential file
first, then the node's server role.

#### Option A — Static keys (credential Secret)

Fill in your keys (see [`examples/configure.example`](examples/configure.example)):

```ini
ncloud_access_key_id = YOUR_ACCESS_KEY
ncloud_secret_access_key = YOUR_SECRET_KEY
secretmanager_api_url = https://ocapi-kr.ncloud.com/secretmanager/api/v1
```

That URL is the KR endpoint for secrets under an isolated KMS key. Pick yours
from [Secret Manager API endpoints](#secret-manager-api-endpoints).

Leave the keys at the top of the file, under no section header. A `[default]`
header — the shape an AWS credential file has — parses without error, but only
the literal `[DEFAULT]` names the top level here, so the keys land where the
provider never looks and the pod fails to start with `ncloud_access_key_id and
ncloud_secret_access_key must be set`.

```bash
kubectl -n kube-system create secret generic ncp-secrets-store-credentials --from-file=./configure
```

> This key is used for **every** request the provider serves, in every namespace.
> Read [Security](#security) before using this on a shared cluster.

#### Option B — NKS node server role

Create a Server-type Sub Account role carrying the
`NCP_VPC_SECRET_MANAGER_VIEWER` policy and attach it to the node pool. This
skips the Secret entirely: the provider reads temporary credentials from the
instance metadata API and refreshes them before they expire.

The provider speaks [metadata v2](https://api.ncloud-docs.com/docs/en/compute-vmetadata-metadatav2)
only, issuing a session token before each read. Nodes set to either *v1 and v2*
or *v2 (token required)* work; the provider never falls back to v1, which NCP
documents as reachable through an SSRF bug in any pod on the node.

Because there is no credential file to read the endpoint from, pass it as a flag
in the DaemonSet:

```yaml
args: ["--secretmanager-api-url=https://ocapi-kr.ncloud.com/secretmanager/api/v1"]
```

Substitute the endpoint for your region and key type — see
[Secret Manager API endpoints](#secret-manager-api-endpoints).

On startup the provider logs which source won:

```bash
kubectl -n kube-system logs -l app=secrets-store-csi-driver-provider-ncp | grep "credentials resolved"
```

### 3. Deploy the provider

```bash
kubectl apply -f deploy/secrets-store-csi-driver-provider-ncp.yaml
```

## Upgrading

Skip this if you are installing for the first time. It applies to clusters
running a pre-release build, tagged `v0.1.0-<commit>`.

`v1.0.0` refuses malformed configuration instead of working around it, and the
refusals come in two kinds that fail very differently:

- **When the provider starts.** The API URL is validated before the gRPC server
  opens, so a value that no longer passes takes the process down. The DaemonSet
  goes to `CrashLoopBackOff` on rollout, every pod on that node loses its
  provider, and the reason is in the provider's own log — not in any pod event.
- **At mount time.** Everything about the `objects` document is checked per
  mount. Nothing wrong is mounted, the pod stays in `ContainerCreating`, and
  `kubectl describe pod` carries the reason.

With rotation off — the default — a mount-time refusal waits for a pod to
restart, so it can surface long after the upgrade. With
`enableSecretRotation=true` there is no such delay: kubelet re-invokes the
provider periodically, so a running pod hits the refusal on its next re-mount
and stops picking up new values. Audit before you roll out either way.

### Refused when the provider starts

| Setting | Refused because |
|---|---|
| An effective API URL that is not an absolute `https://` URL — `http://`, a missing scheme, embedded userinfo, a query or a fragment | The signature authenticates a request, it does not encrypt one. Earlier builds read only the host and path out of this value, so a wrong scheme, userinfo and a query string were all silently discarded rather than honoured. Only the effective URL is checked: `--secretmanager-api-url` when it is set, `secretmanager_api_url` from the credential file otherwise |

### Refused at mount time

| Setting | Refused because |
|---|---|
| Two entries with the same `path` | The driver keys files by path, so one entry used to overwrite the other and only one file appeared |
| `path` that is not a clean relative path (`./f`, `/f`, `../f`, `a/../b`) | Resolved against the mount directory; an escaping path is rejected before any secret is read |
| A `path` the driver will not write: over 4096 bytes, a name within it over 255 bytes, or a first element beginning with `..` (`..data`) | The driver's own limits — `..data` and `..<timestamp>` are names its writer keeps for itself in the mount directory. It applied them after every secret had been fetched; they are applied before now |
| One `path` used as a file and as a directory by another entry (`a` and `a/b`) | The driver creates one or the other and then fails the whole mount on the second — after every secret has been fetched. Refused up front instead |
| A field that is not `objectName`, `objectType`, `path` or `secretKey`, or any of them twice | A misspelling like `secretKye` used to be dropped, which mounted the **whole** secret where one field was asked for |
| `secretKey` written with no value (`secretKey:`, `''`, `""`, `~`, `null`) | Same outcome as the misspelling, and it is what a template renders when its value is unset. Omit the field to mount the whole secret |
| An `objects` document with no entries | Earlier builds returned a successful empty mount, so a fully commented-out list looked like it worked |
| More than one YAML document in `objects`, including an empty one left by a trailing `---` | **This row and every row below it refuse configuration that mounts today.** yaml reads the first document and drops the rest in silence, so entries after a separator never reached the driver and the pod started with files missing. A trailing separator loses nothing and is refused all the same, because accepting it would go back to discarding whatever a third document held |
| More than 1000 entries, or an `objects` document over 128 KiB | Bounds the work one SecretProviderClass can ask of a node's provider. Neither limit existed in a pre-release build, so both refuse documents that mount today; past an average entry of about 131 bytes it is the byte limit that binds first. Neither can be read by eye — [Auditing what you have](#auditing-what-you-have) counts them |
| `nodePublishSecretRef` on the pod's volume | The driver forwards the referenced Secret, and this provider has never read it. The mount succeeded, signed with the one cluster-wide credential, while the pod's spec said it used its own — the only shape of this a refusal can fix. A mount carrying the pod's service account tokens in that same field is not refused for that alone: the refusal is on a key this provider must not ignore, not on the field being non-empty. Kubelet, not the driver, decides where they go: the volume context by default, and the secrets field where the CSIDriver sets `serviceAccountTokenInSecrets`. Chart 1.6.0 sets it for you whenever `tokenRequests` is non-empty on Kubernetes 1.35 and up, so `tokenRequests` on the shared driver is the thing to look for. See [Limitations](#limitations) |

YAML anchors and merge keys (`<<: *base`, including entries that override a
merged field) keep working.

### Auditing what you have

The commands below that end in `sort` exit 0 on empty input: run those under
`set -o pipefail`, or a `kubectl` that was refused and a missing `jq` both read
as a cluster with nothing to fix. The rest cannot report a success they never
had — a bare `kubectl` carries its own status, and the ones ending in `grep`
exit 1 when there is nothing to print — though only their stderr tells a
refusal apart from a clean cluster.

Print every SecretProviderClass with its `objects` document, and read each one
against the mount-time table:

```bash
kubectl get secretproviderclass -A \
  -o jsonpath='{range .items[*]}=== {.metadata.namespace}/{.metadata.name}{"\n"}{.spec.parameters.objects}{"\n"}{end}'
```

Repeated `path` values and misspelled field names are the two worth reading for
carefully: both were accepted by earlier builds, and both did something other
than what they read as. A valueless `secretKey` can be found mechanically:

```bash
kubectl get secretproviderclass -A \
  -o jsonpath='{range .items[*]}=== {.metadata.namespace}/{.metadata.name}{"\n"}{.spec.parameters.objects}{"\n"}{end}' \
  | grep -nE "^=== |^[[:space:]]*secretKey:[[:space:]]*(''|\"\"|~|null|Null|NULL)?[[:space:]]*(#.*)?\$"
```

The `=== ` lines are matched too, so each hit is preceded by the
SecretProviderClass it came from. This reads line by line, so it covers the
block style the examples use; an entry written in flow style
(`- {objectName: s, secretKey: }`) has to be read by eye.

A document separator inside the block is worth a second look: it refuses a
mount which succeeds today, and unlike the limits below there is no threshold
to stay under -- one line crosses it.

```bash
kubectl get secretproviderclass -A \
  -o jsonpath='{range .items[*]}=== {.metadata.namespace}/{.metadata.name}{"\n"}{.spec.parameters.objects}{"\n"}{end}' \
  | grep -nE "^=== |^[[:space:]]*(---|\.\.\.)([[:space:]].*)?$"
```

An opening `---`, and a closing `...` with only comments or blank lines after
it, are fine; a second `---`, or more YAML after a `...`, is not.
Separators between Kubernetes resources live outside
`spec.parameters.objects` and do not appear in this output.

Size and entry count are the two refusals nothing in the document makes
visible. Size first:

```bash
kubectl get secretproviderclass -A -o json | jq -r '.items[]
  | select(.spec.provider == "ncp")
  | "\(.spec.parameters.objects // "" | utf8bytelength)\t\(.metadata.namespace)/\(.metadata.name)"' \
  | sort -rn
```

Bytes, then the SecretProviderClass; over 131072 is refused. `utf8bytelength`
is the count the provider applies — `length` would count characters and read
short for any name that is not ASCII.

Entries have to be counted by a YAML parser rather than by grepping for `- `:
a list written in flow style, indented below a comment, or opened with a bare
`-` reads as **zero** entries to a line match while the provider counts every
one of them. Over 1000 entries is refused, and 1001 entries averaging under
about 131 bytes stay below the byte cap, so the size column above will not
surface them. This one needs [mikefarah/yq](https://github.com/mikefarah/yq)
v4, and `bash` — `pipefail` is what keeps a failed decode from reading as an
empty document:

```bash
kubectl get secretproviderclass -A -o json \
  | jq -r '.items[] | select(.spec.provider == "ncp")
      | "\(.metadata.namespace)/\(.metadata.name) \(.spec.parameters.objects // "" | @base64)"' \
  | while read -r name doc; do
      n=$(set -o pipefail
          printf %s "$doc" | base64 -d | yq 'select(document_index == 0) | length' 2>/dev/null) \
        || { printf 'unparseable\t%s\n' "$name" >&2; continue; }
      printf '%s\t%s\n' "$n" "$name"
    done | sort -rn
```

Each document is counted on its own, so one that does not parse is named on
stderr and the rest of the audit still runs — handing the whole list to `yq` at
once ends it on the first empty `objects`, and a name buried in the sorted
output is a name nobody reads. A document split by `---` counts only the first
document `yq` sees; the separator audit above is what catches that.

`nodePublishSecretRef` is not in the SecretProviderClass either — it sits on the
pod's volume, and it is refused now rather than ignored, so a pod carrying one
stops mounting at its next restart. `enableSecretRotation=true` does not bring
that forward on driver v1.6.0: kubelet re-mounts, the provider refuses, and the
driver swallows the error on a re-mount ([kubernetes#121271](https://github.com/kubernetes/kubernetes/issues/121271)),
so kubelet sees success, no event is written, the files keep their last values,
and only the driver's own log says anything. Find them before they restart:

```bash
kubectl get pods -A -o json \
  | jq -r '.items[] | . as $p | .spec.volumes[]?
      | select(.csi.driver == "secrets-store.csi.k8s.io" and .csi.nodePublishSecretRef)
      | "\($p.metadata.namespace)/\($p.metadata.name)\t\(.name)\t\(.csi.nodePublishSecretRef.name)"' \
  | sort
```

Pod, volume, then the Secret it named. Anything listed was already being served
by the cluster-wide credential rather than by that Secret, so removing the ref
changes nothing about what the pod reads.

The API URL is not in any SecretProviderClass. It comes from the credential
Secret, or from the flag on the DaemonSet, so print both — but only one of them
is used, and it is the flag whenever the flag is set:

```bash
kubectl -n kube-system get secret ncp-secrets-store-credentials \
  -o jsonpath='{.data.configure}' | base64 -d | grep secretmanager_api_url
kubectl -n kube-system get ds secrets-store-csi-driver-provider-ncp \
  -o jsonpath='{.spec.template.spec.containers[*].args}'
```

After rolling out, confirm the provider actually came up before you wait on pod
restarts:

```bash
kubectl -n kube-system rollout status ds/secrets-store-csi-driver-provider-ncp --timeout=2m
```

### Mounted values that change

Extracting a number, an array or an object with `secretKey` produces a different
file than it used to. The earlier value was wrong — every value went through a
float, and re-encoded objects came back with their keys reordered. Strings are
unaffected.

| Secret value | Before | Now |
|---|---|---|
| `{"ratio": 0.75}` | `1` | `0.75` |
| `{"amount": 12345678901234567890}` | `12345678901234567168` | `12345678901234567890` |
| `{"ids": [12345678901234567890]}` | `[12345678901234567000]` | `[12345678901234567890]` |
| `{"opt": {"b":1,"a":2}}` | `{"a":2,"b":1}` | `{"b":1,"a":2}` |

`SecretProviderClassPodStatus.status.objects[].id` also changes: it is the
object's `path` now, so that two entries naming one secret stay distinct.

### arm64 nodes

The manifest carries `kubernetes.io/arch: amd64`, because released images are
amd64. On a cluster with arm64 nodes the provider is not scheduled there and
pods on those nodes cannot mount secrets. To use them, build a multi-arch image
into a registry you can push to, point the manifest at it, and drop the
selector:

```bash
make docker-push REGISTRY=<your-registry> VERSION=v1.0.0 \
  PLATFORMS=linux/amd64,linux/arm64
```

Then edit `image:` in `deploy/secrets-store-csi-driver-provider-ncp.yaml` to
that registry and remove the `kubernetes.io/arch: amd64` line.

### Rolling back

Setting the image tag back restores the previous behaviour, with no
configuration change. Keep the repository your DaemonSet already uses —
pre-release images were published to a number of regional registries, and the
one below is only an example:

```bash
kubectl -n kube-system get ds secrets-store-csi-driver-provider-ncp \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
kubectl -n kube-system set image ds/secrets-store-csi-driver-provider-ncp \
  secrets-store-csi-driver-provider-ncp=<that repository>:<previous tag>
```

This is a way to get pods running again, not a fix. Everything in the tables
above comes back with it: a misspelled `secretKey` mounts the whole secret, a
repeated `path` silently drops a file, an escaping path is only caught after the
secret has been read, and extracted numbers go back to being wrong. So do things
that are not in the tables, depending on how far back you go — a byte of the
secret quoted in a parse error, a socket mode left to the container's umask,
and in some intermediate builds an API URL's credentials written to the log.
Roll forward once the configuration is fixed.

## Usage

### 1. Register a secret in NCP Secret Manager

In the NCP console, create a secret (e.g. `my-secret`) holding `id` and `password` keys.

### 2. Create a SecretProviderClass

See [`examples/secretproviderclass.yaml`](examples/secretproviderclass.yaml):

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: my-secret
spec:
  provider: ncp
  parameters:
    objects: |
      - objectName: "my-secret"
        objectType: "secretmanager"
        path: "my-secret.txt"
      - objectName: "my-secret"
        objectType: "secretmanager"
        secretKey: "id"
        path: "id.txt"
```

### 3. Mount the secret in a pod

See [`examples/pod.yaml`](examples/pod.yaml):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
    - name: my-pod
      image: busybox
      command: ["sleep", "1000000"]
      volumeMounts:
        - name: my-secret
          mountPath: /var/secrets
          readOnly: true
  volumes:
    - name: my-secret
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: my-secret
```

The secrets become files in the mount path:

```bash
kubectl exec my-pod -- cat /var/secrets/my-secret.txt
kubectl exec my-pod -- cat /var/secrets/id.txt
```

## Configuration

### SecretProviderClass parameters

| Field | Required | Description |
|-------|----------|-------------|
| `objectName` | yes | Secret name registered in NCP Secret Manager |
| `objectType` | yes | Object type; only `secretmanager` is supported |
| `path` | yes | Relative path under the mount directory; subdirectories are created as needed |
| `secretKey` | no | Extract a single key from the JSON secret. If omitted, the whole key/value JSON is mounted. Writing it without a value (`secretKey:`) is rejected rather than treated as omitted |

### Validation

`objects` is parsed strictly, as a single YAML document, and anything that
breaks a rule fails the mount rather than being worked around: an unknown or
repeated field, a `path` that escapes the mount directory, collides with another
entry's, or exceeds the limits the driver writes under, a `secretKey` written
with no value, a second document, no entries at all, more than 1000 of them, or
a document over 128 KiB. The pod stays in `ContainerCreating` and `kubectl
describe pod` carries the rule — and, for the checks that apply to one entry,
which entry. [Refused at mount time](#refused-at-mount-time) lists them all,
with what each one used to do instead.

A document that does not parse at all is reported element by element, one line
each, which a 128 KiB document can run to millions of lines. That message is cut
to its first complaints and ends with a count of what was dropped; fix those and
re-apply to see the next.

The API URL is checked once, at startup, and a bad one stops the provider rather
than a mount — see [Refused when the provider starts](#refused-when-the-provider-starts).

### Command-line flags

| Flag | Default | Description |
|------|---------|-------------|
| `--endpoint` | `/etc/kubernetes/secrets-store-csi-providers/ncp.sock` | gRPC unix socket path |
| `--credential-path` | `/credentials/configure` | NCP credential file path |
| `--secretmanager-api-url` | (none) | Secret Manager API URL. Takes precedence over `secretmanager_api_url` in the credential file; required when no credential file is mounted |

> The socket directory must match the driver's provider volume path. If you changed
> the driver's `providersDir`, set `--endpoint` and the DaemonSet `hostPath` accordingly.

### Secret Manager API endpoints

The endpoint depends on the region and on which KMS key protects the secret.
Note that the path differs too, not just the host.

| Region / key | Endpoint |
|---|---|
| KR, secrets under an isolated KMS key | `https://ocapi-kr.ncloud.com/secretmanager/api/v1` |
| KR, secrets under the global KMS key | `https://secretmanager.apigw.ntruss.com/api/v1` |
| JPN | `https://ocapi-jp.ncloud.com/secretmanager/api/v1` |

Examples throughout this README use the KR isolated-key endpoint. New KR secrets
use an isolated key, while secrets created earlier under the global key keep
working on their own endpoint. See the
[Secret Manager API overview](https://api.ncloud-docs.com/docs/en/secretmanager-api-overview)
for the authoritative list.

## Security

### Credentials are cluster-wide

The provider loads one NCP API key — from its mounted credential file or the
node's server role — and uses it for every request it serves. It does **not**
scope access by namespace: the
`pod.namespace` carried on a mount request is written to the provider log, but is
never used for authorization.

That means **anyone who can create a `SecretProviderClass` and a pod that mounts
it can read any secret the key can reach**, no matter which namespace they are in.

Before running this on a shared or multi-tenant cluster:

- Restrict who may create `SecretProviderClass` resources and pods, via RBAC.
- Issue the key from a dedicated NCP Sub Account scoped to only the secrets this
  cluster needs, rather than a broadly privileged account key.
- Treat the credential `Secret` in `kube-system` as a cluster-wide secret, and
  restrict read access to it.

RBAC on `SecretProviderClass` does not close the whole path. The provider
creates its gRPC socket, mode `0755`, inside the hostPath directory kubelet owns
as `root:root`, so a pod that mounts
`/etc/kubernetes/secrets-store-csi-providers` and runs as root can call `Mount`
directly and read any secret the key can reach, without creating a
`SecretProviderClass` at all. The mode keeps a plain unprivileged process out,
but not one holding `CAP_DAC_OVERRIDE`, which container runtimes grant by
default — so treat the mode as a speed bump, not the boundary.

Closing it means restricting hostPath mounts, which the
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
`baseline` profile does, enforced through Pod Security Admission. Apply it to
the namespaces that run workloads, **not** to the namespace holding the provider
and the driver: both mount hostPath, and the driver additionally runs
privileged, so enforcing `baseline` there stops them from being scheduled at
all — and with them, every secret mount in the cluster. Admission only refuses
new pods, so nothing happens when the label goes on: the running provider keeps
serving. It breaks later and a node at a time — a new node, or a restart, leaves
that node without a provider, and a full rollout takes the cluster — by which
point the label is no longer the obvious suspect.

Per-pod credentials (`nodePublishSecretRef`) are refused rather than ignored —
see [Limitations](#limitations).

### Choosing an authentication method

| Method | When to use | Trade-off |
|---|---|---|
| **Credential file (static keys)** | Any cluster; when you want a Sub Account key scoped to specific secrets | Explicit and auditable, but you store and rotate a long-lived key yourself |
| **NKS node server role** | NKS clusters | No long-lived key to store, and credentials refresh automatically — but **every pod on that node can read the same credentials** through the metadata API |

The server role option widens exposure rather than narrowing it: with a mounted
Secret only this provider holds the key, whereas a node role is readable by any
pod scheduled to that node. This DaemonSet tolerates every taint, so it runs on
all nodes. Use a dedicated or tainted node pool if that matters to you.

### Container privileges

The provider runs as root because it creates its gRPC socket inside a hostPath
directory that kubelet owns as `root:root 0755`, and hostPath volumes ignore
`fsGroup`. Everything else is dropped in
[`deploy/secrets-store-csi-driver-provider-ncp.yaml`](deploy/secrets-store-csi-driver-provider-ncp.yaml):
`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, all Linux
capabilities dropped, and the default seccomp profile. Unlike the driver itself,
the provider does **not** need `privileged: true`.

The provider makes no Kubernetes API calls, so it needs no RBAC at all and its
ServiceAccount is deployed with `automountServiceAccountToken: false`.

## Limitations

| Limitation | Detail |
|---|---|
| No namespace isolation | One cluster-wide credential, no per-namespace scoping — see [Security](#security) |
| No per-pod credentials | `nodePublishSecretRef` is refused at mount time rather than ignored. One credential serves every pod in every namespace, so there is nothing for a per-pod Secret to narrow — see [Security](#security) |
| Reported object versions are constant | Every object is reported with version `1`. Rotation is off by default; with `enableSecretRotation=true` kubelet re-invokes the provider periodically and the driver writes back whatever files it receives without comparing versions, so rotated values do reach mounted files — and synced Secrets, but up to 5 minutes later: an unchanged version leaves the driver nothing to react to, so it picks the new files up when its status controller requeues, every 5 minutes. The constant surfaces only in `SecretProviderClassPodStatus.status.objects[].version`, which never changes. With rotation off, restart the pod to pick up a new value |
| Nothing is cached between mounts | Within one mount each distinct secret is fetched once, however many entries name it. Across mounts nothing is kept: every mount repeats the name→ID lookup, paged from the first page, and the value fetch |
| At most 1000 objects per SecretProviderClass, and 128 KiB of `objects` | Whichever is reached first — past an average entry of about 131 bytes the byte cap binds before the count does. A backstop against an oversized payload, not a budget: entries naming an already-fetched secret cost no extra API call |
| No bound on concurrent mounts | Nothing limits how many mounts the provider serves at once: `MaxConcurrentStreams` is left unset, and each mount holds its own `objects` document and every value it fetched until it answers. The densest document the 128 KiB cap still admits peaks near 53 MiB of RSS, so two of those fit under the DaemonSet's `limits.memory: 128Mi` and three do not — and the pod being killed takes every secret mount on that node with it, not just the mounts that caused it. The sizing is for a deliberately dense document; ordinary ones are orders of magnitude smaller |
| No cap on the total size of one mount | The `objects` document is capped before it is parsed, and each API response is capped on its own, but the values fetched for one mount and the response built from them have no combined limit. The driver refuses a response over its `--max-call-recv-msg-size` (default 4 MiB), after every secret has been fetched — a total is only knowable once they have been, and the provider is not told what the driver will accept, so it has nothing to refuse against earlier |
| `secretmanager` only | `objectType` accepts no other value |
| Released images are `linux/amd64` | Other architectures can be built from source — see [Development](#development) |
| Credential file is not hot-reloaded | Static keys carry no expiry, so the first pair read is cached for the process lifetime and the file is never consulted again. Rotating the NCP key and retiring the old one therefore fails **every mount served by a provider pod that predates the rotation** — it keeps presenting the retired key, and nothing invalidates the cache on a 401 — until the DaemonSet is restarted. A provider pod that starts afterwards reads the new key and is unaffected, which is what makes this easy to miss. Roll the DaemonSet as part of rotating the key, before the old key is disabled. Server role credentials carry an expiry and refresh on their own |
| Failed refreshes are retried per request | While a credential refresh keeps failing (for example an unreachable metadata API) and the cached value is inside its refresh window, each outbound API call (several per mount) retries the provider chain under one lock, so requests queue behind the metadata timeout. The cached credential is still served until it truly expires, so mounts succeed — they just slow down |

### Rotation multiplies Secret Manager calls

Rotation is disabled by default, and leaving it off costs one round of API calls
per pod start. Turning it on with `enableSecretRotation=true` is not a small
change in call volume, so budget for it before you do.

Driver v1.6.0 removed its rotation controller; re-mounts now ride kubelet's pod
sync, which runs about once a minute per pod. `rotation-poll-interval` no longer
drives a poller — in v1.6.0 it became a cache duration measured from the mount
directory's timestamp — so do not count on it to bring the rate down
([#2061](https://github.com/kubernetes-sigs/secrets-store-csi-driver/issues/2061)
tracks the loss of control over the period). Every re-mount calls this provider
again, so daily calls come out at roughly:

```
pods × distinct secrets per pod × (list pages + 1) × ~1,440
```

Thirty distinct secrets across a dozen pods is on the order of a million calls a
day. Note that it counts *distinct* secrets: entries that name a secret already
fetched in the same mount — the common one-secret-many-`secretKey` pattern — add
nothing, because the provider fetches each secret once per mount.

If you do not need values to change under a running pod, leave rotation off and
restart pods to pick up new values. If you do need it, keep the number of
distinct secrets per pod small, and watch your Secret Manager call volume.

## Monitoring

A health endpoint is served on port 8080:

```bash
kubectl -n kube-system exec <provider-pod> -- wget -qO- localhost:8080/health
```

Logs:

```bash
kubectl -n kube-system logs -l app=secrets-store-csi-driver-provider-ncp
```

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Authentication failure | NCP Access/Secret key in the credential Secret, or the Sub Account role attached to the node pool. Also the node's clock: the signature carries a timestamp, so a node that has drifted is refused with the same 401 a wrong key gets. The API's own message is quoted in the provider log and tells the two apart |
| `ncloud_access_key_id and ncloud_secret_access_key must be set`, but both are in the credential file | A section header above them. Only the literal `[DEFAULT]` names the top level; `[default]`, `[Default]` and `[profile default]` parse fine and hide the keys |
| Secret not found | The secret name exists in NCP Secret Manager |
| Mount fails | The Secrets Store CSI Driver is installed and running |
| Mount fails with `ResourceExhausted`, `received message larger than max` | The values for one mount exceed the driver's `--max-call-recv-msg-size` (default 4 MiB); the numbers in the message are the response and that limit. Split the SecretProviderClass across volumes, or raise the driver's flag. The provider log says `returning secrets` for the same mount: it hands the response to the driver and never learns what became of it |
| Provider not called | `--endpoint`/`hostPath` matches the driver's provider socket directory |
| Mounted value is stale after rotating the secret | Rotation is off by default — reinstall the driver with `--set enableSecretRotation=true`. See [Limitations](#limitations) |

## Development

```bash
make build     # build the binary into bin/
make test      # run tests with the race detector
make lint      # run golangci-lint
make fmt       # apply gofmt/goimports
```

`make lint` requires [golangci-lint](https://golangci-lint.run/) v2.

### Building the image

Released images target `linux/amd64`. The build cross-compiles for whichever
platform you ask for, so other architectures build the same way:

```bash
make docker-build                    # linux/amd64, loaded into the local daemon
make docker-push VERSION=v1.0.0      # build and push
```

Multi-platform images cannot be loaded into the local daemon, so pass
`PLATFORMS` to `docker-push`:

```bash
make docker-push PLATFORMS=linux/amd64,linux/arm64 VERSION=v1.0.0
```

Equivalent without `make`:

```bash
VERSION=$(git describe --tags --always)
docker buildx build --platform linux/amd64 --build-arg VERSION=$VERSION \
  -t nks.kr.ncr.ntruss.com/secrets-store-csi-driver-provider-ncp:$VERSION --load .
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
