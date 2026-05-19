# External VEX Ingestion for Kubescape

| | |
|---|---|
| Status | Draft – discussion |
| Author | yashsadhwani544@gmail.com |
| Date | 2026-05-19 |
| Related work | [SecurityException CRD design](https://github.com/kubescape/kubevuln/blob/main/docs/security-exception-design.md) (LFX Mentorship, June–August 2026) |

## 1. Summary

Kubescape today **produces** OpenVEX documents from its own scan results but does not **consume** VEX produced by anyone else. This proposal adds a controller that pulls upstream vendor VEX feeds (Red Hat CSAF/VEX, Chainguard/Wolfi, and similar) on a schedule, persists them as first-class objects alongside the VEX documents kubevuln already writes, and joins them into the vulnerability manifest pipeline so that vendor‑declared `not_affected` / `fixed` statements suppress matching findings before they ever reach a user.

A new namespaced CRD, `VEXSource`, declares **where** to fetch a feed, **how often**, and **which images it applies to**. The operator’s existing `WatchHandler` / `CooldownQueue` machinery handles change detection and rescan dispatch.

The feature composes with the SecurityException CRD work being built this summer: a vendor `not_affected` statement is functionally identical to a user-authored `vulnerabilities[]` exception, and the same matching/justification fields already map onto OpenVEX in that design.

## 2. Motivation

Distribution base images dominate the CVE counts in most clusters. A scan of a stock `nginx`, `alpine`, `python`, or any RHEL UBI image surfaces dozens of CVEs that the distribution maintainer has already triaged, often marked `not_affected` because the vulnerable code path isn't compiled in, the package isn't shipped, or an inline mitigation exists. Two industry shifts make this worth acting on now:

1. **Vendors are publishing machine-readable VEX.** Red Hat now publishes a CSAF/VEX file for every CVE that touches its portfolio at `https://security.access.redhat.com/data/csaf/v2/vex/` ([announcement](https://www.redhat.com/en/blog/csaf-vex-documents-now-generally-available), [feed root](https://security.access.redhat.com/data/csaf/v2/vex/)). Chainguard publishes OpenVEX for Wolfi/Chainguard Images via `wolfictl` ([advisories](https://images.chainguard.dev/directory/image/wolfi-base/advisories), [docs](https://edu.chainguard.dev/chainguard/chainguard-images/staying-secure/security-advisories/managing-advisories/)). Others (SUSE, Debian Security Tracker exports, GitLab release artifacts) are moving the same direction.
2. **Scanners are ready to consume it.** Grype, the engine kubevuln already runs, supports OpenVEX via `--vex` ([Chainguard/Anchore announcement](https://www.chainguard.dev/unchained/vexed-then-grype-about-it-chainguard-and-anchore-announce-grype-supports-openvex)) and added a CSAF VEX transformer in [v0.111.0](https://github.com/anchore/grype/releases/tag/v0.111.0) ([OpenSSF write-up](https://openssf.org/blog/2023/12/20/openvex-and-open-source-vulnerability-scanners-how-the-dynamic-duo-improves-vulnerability-management/)).

Kubescape was the [first open-source project to ship VEX generation](https://kubescape.io/blog/2023/12/07/kubescape-support-for-vex-generation/). Closing the loop to also consume upstream VEX is a natural and visible follow-up.

### What exists today (verified)

- [`kubevuln/config/config.go` L34](https://github.com/kubescape/kubevuln/blob/main/config/config.go#L34): `vexGeneration` config flag, default `false`.
- [`kubevuln/core/services/scan.go` L355](https://github.com/kubescape/kubevuln/blob/main/core/services/scan.go#L355): after each CVE manifest is produced, if generation is enabled, `cveRepository.StoreVEX(...)` is called.
- [`kubevuln/repositories/apiserver.go`](https://github.com/kubescape/kubevuln/blob/main/repositories/apiserver.go) `createVEX` / `updateVEX`: builds an OpenVEX 0.2.0 document from kubevuln's own scan output and persists it.
- VEX is stored as `OpenVulnerabilityExchangeContainer` (`spdx.softwarecomposition.kubescape.io/v1beta1`), schema at [`storage/pkg/apis/softwarecomposition/v1beta1/types.go` L473](https://github.com/kubescape/storage/blob/main/pkg/apis/softwarecomposition/v1beta1/types.go#L473): author/role/timestamp/version metadata plus a list of OpenVEX statements. An example object lives at [`storage/artifacts/openvulnerabilityexchangecontainer/example-01.yaml`](https://github.com/kubescape/storage/blob/main/artifacts/openvulnerabilityexchangecontainer/example-01.yaml).
- The grype adapter ([`kubevuln/adapters/v1/grype_to_domain.go`](https://github.com/kubescape/kubevuln/blob/main/adapters/v1/grype_to_domain.go)) does **not** currently invoke grype's `--vex` path; no external VEX is consumed during matching.

So the storage CRD shape, the OpenVEX type tree, and the scan-pipeline hook point all already exist. What is missing is (a) a source of external VEX statements and (b) a join step that applies them to scan output.

## 3. Goals / Non-goals

**Goals**

- Declarative, GitOps-friendly subscription to one or more upstream VEX feeds.
- Pull, validate, and persist VEX documents in the existing `OpenVulnerabilityExchangeContainer` CR shape (or a sibling kind; see open questions).
- Apply externally-sourced `not_affected` / `fixed` statements to vulnerability manifests so suppressed CVEs do not surface in dashboards or trigger alerts.
- Provenance preserved end-to-end: every suppressed match records which VEX document and which statement caused the suppression.
- Support both OpenVEX JSON and Red Hat-style CSAF VEX (grype handles both).

**Non-goals (for v1)**

- Authoring/editing VEX inside the cluster. SecurityException CRDs remain the user-facing authoring surface; this proposal is read-only ingestion of third-party data.
- Signing or attestation verification of fetched VEX documents (cosign / Rekor integration); desirable, deferred.
- Cross-cluster federation, mirroring, or republishing feeds.
- Replacing kubevuln's own VEX generation; the two coexist.

## 4. Proposed Design (rough)

### 4.1 New CRD: `VEXSource`

Namespaced, `kubescape.io/v1beta1`. Sketch:

```yaml
apiVersion: kubescape.io/v1beta1
kind: VEXSource
metadata:
  name: redhat-csaf
spec:
  url: https://security.access.redhat.com/data/csaf/v2/vex/
  format: csaf           # csaf | openvex
  refreshInterval: 6h
  imageMatch:            # which scanned images this feed is authoritative for
    - "registry.access.redhat.com/*"
    - "registry.redhat.io/*"
  trust:
    requireSignature: false   # placeholder for cosign verification (future)
status:
  lastFetched: ...
  lastError: ...
  documentsIngested: 1423
```

Cluster-scoped variant (`ClusterVEXSource`) follows the same pattern as `ClusterSecurityException`.

`imageMatch` is the critical scoping field: a Red Hat VEX statement should not be applied to a Debian-based image just because the CVE IDs overlap. Glob patterns on the image reference are the minimum; later we can layer purl/distro match as kubevuln gains the data (the SecurityException design already calls out purl-based product matching as a deferred extension).

### 4.2 Fetcher / controller

Lives in the [operator](https://github.com/kubescape/operator) repo next to the existing watchers. Re-uses:

- [`operator/watcher/watchhandler.go`](https://github.com/kubescape/operator/blob/main/watcher/watchhandler.go) (`WatchHandler` pattern) for the `VEXSource` informer.
- [`operator/watcher/cooldownqueue.go`](https://github.com/kubescape/operator/blob/main/watcher/cooldownqueue.go) to debounce rapid spec changes.
- A new periodic worker keyed on `refreshInterval` (jittered) that performs the HTTP/OCI fetch.

For each successful fetch the controller:

1. Normalizes documents to OpenVEX 0.2.0 in memory (grype's CSAF transformer is the reference here; we may import the same conversion or call out to a small library).
2. Computes a content hash; if unchanged, no-op.
3. Writes/updates one or more `OpenVulnerabilityExchangeContainer` objects, labeled to mark them as externally-sourced (e.g. `kubescape.io/vex-source: redhat-csaf`) so they are not confused with kubevuln-generated VEX.
4. Updates `VEXSource.status` and emits Events on transitions.

To bound the worst-case behavior of the controller, v1 should enforce hard fetch-safety defaults at the fetcher boundary (before normalization). Suggested starting values, all overridable later:

- request timeout: 10 s per HTTP call
- max response body: 50 MB per document
- max documents ingested per sync: 10 000 (feeds larger than this require an incremental cursor — see §5 on feed volume)
- retry policy: 3 attempts, exponential backoff with ±20 % jitter
- stale-data behavior: after N consecutive failed syncs, mark `VEXSource.status` as `Stale`, emit an Event, and back off to `refreshInterval × 4` until a successful sync

### 4.3 Join into the vuln-manifest pipeline

Two integration points, in order of complexity:

**Option A: at scan time, via grype's native `--vex`.**
kubevuln's grype adapter writes the relevant external VEX documents to a per-scan temp directory and invokes grype with one `--vex <file>` per document (the flag is a `stringArray` of file paths, not a directory — see [`cmd/grype/cli/options/grype.go`](https://github.com/anchore/grype/blob/main/cmd/grype/cli/options/grype.go) and [`grype/vex/openvex/implementation.go`](https://github.com/anchore/grype/blob/main/grype/vex/openvex/implementation.go) `ReadVexDocuments` → `openvex.MergeFiles`). OpenVEX and CSAF documents can be mixed in the same invocation; CSAF VEX support landed in [grype v0.99.0](https://github.com/anchore/grype/releases/tag/v0.99.0) (PR [#1826](https://github.com/anchore/grype/pull/1826)) with a refined transformer in [v0.111.0](https://github.com/anchore/grype/releases/tag/v0.111.0) (PR [#3349](https://github.com/anchore/grype/pull/3349)). Matches that VEX suppresses appear in grype's `ignoredMatches` output, which the adapter already has a field for ([`grype_to_domain.go` L14](https://github.com/kubescape/kubevuln/blob/main/adapters/v1/grype_to_domain.go#L14)). This is the cleanest path because the filtering logic lives where it already lives, in grype, and the resulting CVE manifest is already “VEX-aware” by the time anyone else reads it.

**Option B: post-hoc filtering in the repository layer.**
Apply VEX statements in `cveRepository.StoreCVE` / `StoreCVESummary`, mirroring how the existing `filteredCvep` is derived from relevance and exceptions today ([`scan.go` L340-L362](https://github.com/kubescape/kubevuln/blob/main/core/services/scan.go#L340-L362)). More code to write, but doesn't require kubevuln to materialize files on disk for grype.

A is preferred; B is the fallback if grype's file-based VEX intake is awkward for kubevuln's container/lifecycle model. Either way, the suppressed-match record carries a reference to the source `VEXSource` plus statement ID for provenance.

### 4.4 Composition with the SecurityException CRD (LFX 2026)

The [SecurityException CRD design](https://github.com/kubescape/kubevuln/blob/main/docs/security-exception-design.md) being built for the June–August 2026 LFX Mentorship term already defines a `vulnerabilities[]` section whose status/justification enums **mirror OpenVEX** (see the "VEX Status/Justification Enums" and "OpenVEX Compatibility" sections of that doc). A vendor VEX statement and a user-authored vulnerability exception are therefore the same logical object expressed in two formats.

That suggests an optional bridge: for any external statement with `status: not_affected`, materialize a synthetic `SecurityException` (cluster-scoped, owner-referenced to the `VEXSource`) with the same justification/impact text. Benefits:

- One unified UI surface (the Headlamp plugin being built this summer to view SecurityException resources) shows both user-authored and vendor-supplied suppressions.
- The provenance Events scheme from the SecurityException design extends to vendor sources for free.
- Cloud-vs-CRD precedence rules already in scope for SecurityException can be reused (e.g. user-authored CRDs override conflicting vendor VEX, or vice versa; to be decided).

This bridge is **optional** and orthogonal to v1. The minimum-viable VEX ingestion does not depend on SecurityException landing first; the two efforts can ship independently and be linked later via a follow-up.

### 4.5 What it touches

| Repo | Change |
|---|---|
| [`armoapi-go`](https://github.com/kubescape/armoapi-go) or [`k8s-interface`](https://github.com/kubescape/k8s-interface) | `VEXSource` Go types (location follows whatever convention SecurityException lands on). |
| [`storage`](https://github.com/kubescape/storage) | Either reuse `OpenVulnerabilityExchangeContainer` with a label/annotation marking source, or add a sibling kind. CRD YAMLs hand-maintained. |
| [`operator`](https://github.com/kubescape/operator) | New watcher + periodic fetcher under `watcher/`. |
| [`kubevuln`](https://github.com/kubescape/kubevuln) | Pass relevant external VEX docs into grype via `--vex` (or post-hoc filter), wire provenance into stored CVE manifests. |
| [`helm-charts`](https://github.com/kubescape/helm-charts) | Ship `VEXSource` CRD, default disabled, with an opt-in values flag. |
| [`headlamp-plugin`](https://github.com/kubescape/headlamp-plugin) | Optional: list `VEXSource` objects and show their last-fetch status. |

## 5. Challenges and open questions

- **Trust model.** Red Hat's feed is served over HTTPS but the documents themselves are not signed in OpenVEX/CSAF native form. Should we require cosign attestations, pin TLS roots, or accept HTTPS-of-origin as good enough for v1? Real value vs. complexity tradeoff; likely v1 = HTTPS only, design for future cosign.
- **Feed scoping correctness.** A Red Hat VEX statement about `openssl` in `rhel-9` must not be applied to an `openssl` finding from a Debian image, even though both surface the same CVE ID. OpenVEX's `products` (purl-based) field is the correct match key, but the [SecurityException design](https://github.com/kubescape/kubevuln/blob/main/docs/security-exception-design.md) explicitly defers purl matching as “significant complexity”. We will need to do at least image-reference globbing in v1 and decide whether to attempt purl matching for VEX since the source documents already contain purls.
- **CSAF / OpenVEX normalization fidelity.** grype's [v0.111.0](https://github.com/anchore/grype/releases/tag/v0.111.0) transformer is the reference. Whether to depend on grype's transformer code as a library, vendor it, or re-do the conversion is an early decision.
- **Storage shape.** `OpenVulnerabilityExchangeContainer` was designed assuming one-document-per-image-scan. Vendor feeds are organized by CVE (Red Hat) or by package (Wolfi), not per-image. We either (a) reshape on ingest into per-image documents, (b) introduce a sibling kind `ExternalVEXContainer` that better matches the source organization, or (c) ingest each upstream document verbatim and do the per-image join only at scan time. The third option is the simplest but means storing more objects.
- **Feed volume.** Red Hat's CSAF VEX directory is large (thousands of files) and grows daily. We need incremental fetch (HTTP `If-Modified-Since`, the `changes.csv` index Red Hat publishes) rather than full re-pulls. This is a real engineering concern, not a paper one.
- **Failure modes.** A poisoned or stale feed could silently hide real vulnerabilities. We need: per-feed enable/disable, an "ignore VEX from source X" override, and a way to surface "X CVEs are suppressed by VEXSource Y" in scan output so operators see what is being filtered.
- **Air-gapped clusters.** Mirroring feeds offline (`oras pull`, an OCI ref pointing at a mirrored bundle) needs to be a first-class case. The `url:` field should accept both HTTPS and OCI references.
- **Overlap with cloud exceptions.** ARMO Cloud already returns exception policies through the existing getter. If a cloud exception, a SecurityException CRD, and a vendor VEX statement all touch the same CVE, what wins? Reuse the cloud-vs-CRD precedence rules being defined for SecurityException.
- **Egress posture and RBAC.** `VEXSource.spec.url` is operator-fetched, so a permissive default would let any tenant with `create` on the CRD steer the operator's HTTP client at internal services or cloud metadata endpoints. v1 should restrict accepted schemes to `https://` and `oci://`, deny loopback / link-local / RFC1918 / IPv6 ULA / cloud-metadata destinations, treat redirects as new fetches (re-validated against the same policy), and gate `create`/`update` on `(Cluster)VEXSource` to cluster-admin by default in the shipped RBAC.

## 6. Prior art and references

- [Red Hat: CSAF VEX documents now generally available](https://www.redhat.com/en/blog/csaf-vex-documents-now-generally-available)
- [Red Hat: VEX files for CVEs now generally available](https://www.redhat.com/en/blog/red-hat-vex-files-cves-are-now-generally-available)
- [Red Hat CSAF/VEX overview, Security Data Guidelines](https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/)
- [Red Hat CSAF VEX feed root](https://security.access.redhat.com/data/csaf/v2/vex/)
- [Chainguard: OpenVEX adoption announcement](https://www.chainguard.dev/unchained/chainguard-to-accelerate-vex-adoption-through-openvex-specification)
- [Chainguard Academy: managing security advisories with `wolfictl`](https://edu.chainguard.dev/chainguard/chainguard-images/staying-secure/security-advisories/managing-advisories/)
- [Chainguard: `vulnerability-scanner-support`](https://github.com/chainguard-dev/vulnerability-scanner-support)
- [Grype + OpenVEX announcement (Chainguard / Anchore)](https://www.chainguard.dev/unchained/vexed-then-grype-about-it-chainguard-and-anchore-announce-grype-supports-openvex)
- [Grype v0.111.0 release (CSAF VEX transformer)](https://github.com/anchore/grype/releases/tag/v0.111.0)
- [OpenSSF: OpenVEX and open-source vulnerability scanners](https://openssf.org/blog/2023/12/20/openvex-and-open-source-vulnerability-scanners-how-the-dynamic-duo-improves-vulnerability-management/)
- [OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
- [Kubescape: first OSS project to support VEX generation (Dec 2023)](https://kubescape.io/blog/2023/12/07/kubescape-support-for-vex-generation/)
- [SecurityException CRD design](https://github.com/kubescape/kubevuln/blob/main/docs/security-exception-design.md)
