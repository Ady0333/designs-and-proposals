# Proposal: Adaptive CPE Matching for Trusted Image Vendors in Kubevuln

- **Status:** Draft
- **Scope:** [`kubevuln`](https://github.com/kubescape/kubevuln); [`helm-charts`](https://github.com/kubescape/helm-charts) (config plumbing)
- **Author:** Ben Hirschberg (<ben@armosec.io>)
- **Related:**
  - [anchore/grype#2647](https://github.com/anchore/grype/pull/2647): Echo OS support in Grype (merged)
  - [anchore/grype-db#572](https://github.com/anchore/grype-db/pull/572): Echo provider in grype-db
  - [anchore/vunnel#815](https://github.com/anchore/vunnel/pull/815): Echo vulnerability feed in vunnel

## Summary

Kubevuln enables Grype's CPE-based matching across language ecosystems to
eliminate false negatives. This is the right trade-off for arbitrary images,
but it systematically inflates results for **trusted image vendors** (Echo.ai,
Chainguard, Minimus), vendors that maintain their own authoritative vulnerability
feeds, already integrated upstream into the Grype database. For these images,
CPE name-fuzzing adds only false positives: the vendor's feed already
guarantees completeness.

This proposal introduces a third matching mode, which becomes the **default**:
**CPE matching on, except for images from trusted vendors**, where kubevuln
automatically falls back to Grype's default (ecosystem/feed-based) matching. Vendor identification reuses
Grype's own distro-detection mechanism: no new identification logic and no
vendored code.

## Motivation

Echo.ai reported that Kubevuln shows their images as
2-3x "dirtier" than plain Grype:

| `reg.echohq.com/kafka-ui` | Critical | High |
|---------------------------|----------|------|
| Plain grype (default)     | 7        | 49   |
| Kubevuln                  | 16       | 80   |

The gap comes from CPE matching, which connects packages to CVEs by fuzzing
name candidates. Confirmed false-positive patterns on Echo images:

- `reactor-netty-core` matched as `netty:netty` (separate artifact that
  depends on a fixed netty version and does not embed it)
- `xz` (Java library) matched as `xz-utils` (OS package; the CVEs are
  CLI-specific)
- `protobuf-java` matched as `protobuf` (the C++ implementation, different
  versioning scheme)
- `arrow` (Java) matched as `apache-arrow` (C++-only CVE)

We keep CPE matching on by default because, for a security platform, a false
negative (e.g., a real HTTP-smuggling CVE reachable only via CPE matching) is
worse than a false positive. But that rationale evaporates for vendors whose
business is disclosing every vulnerability in their own images: their feeds
are in the Grype DB, complete by contract. For those images CPE fuzzing has no
upside.

## Goals

- Let users choose between three matching modes:
  1. **CPE matching off**: Grype default behavior everywhere.
  2. **CPE matching on**: current kubevuln behavior everywhere.
  3. **Adaptive (the default)**: CPE matching on, automatically
     disabled per-scan for images identified as coming from a trusted vendor.
- Reuse Grype's existing vendor/distro identification, with no parallel
  mechanism.
- Keep the decision **per-scan**, with no change to the scan pipeline shape.
- Preserve backward compatibility with the existing boolean configuration.

## Non-goals

- Changing how non-trusted images are matched.
- Suppressing or post-filtering individual findings (Risk Acceptance and
  pre-filters remain the tools for that).
- Building a registry-allowlist or signature-verification trust framework
  (discussed as a possible hardening step, see Open Questions).

## Background: how the pieces already fit

**How Grype identifies these vendors.** Trusted-vendor images are standalone
distros. Syft parses the image's `/etc/os-release` into the SBOM's
`LinuxDistribution` field; Grype maps the release ID to a distro type
(`distro.TypeFromRelease`). The Grype version kubevuln already pins (v0.99.1)
recognizes `echo`, `chainguard`, `wolfi`, and `minimos` as first-class distro
types. In other words: **the identification code we want to reuse is already
compiled into kubevuln**; adopting it is a matter of consulting a value we
already compute.

**Where kubevuln already has this information.** In the Grype adapter's
`ScanSBOM` flow, the distro is resolved from the SBOM (`distro.FromRelease`)
*before* the vulnerability matchers are constructed (`getMatchers`). The
matcher set is built fresh on every scan; only the on/off choice is currently
frozen at startup. The hook point for a per-scan decision therefore already
exists; no pipeline restructuring is needed.

**Why feed coverage makes this safe.** The upstream PRs (vunnel, grype-db,
grype) integrate Echo's advisory feed as a provider in the Grype database, the
same standing Chainguard/Wolfi already have. With the vendor's authoritative
feed present, default (non-CPE) matching is complete for those images; the
no-false-negative guarantee shifts from our aggressive matching to the
vendor's disclosure contract.

## Design

### Matching modes

A single configuration value with three modes replaces the current boolean
(`useDefaultMatchers`):

| Mode | Behavior |
|------|----------|
| `off` | Grype defaults everywhere (CPE matching disabled). Equivalent to today's `useDefaultMatchers: true`. |
| `on` | CPE matching enabled everywhere. Equivalent to today's `useDefaultMatchers: false` (today's behavior). |
| `adaptive` **(default)** | CPE matching enabled, except when the scanned image's distro is a trusted vendor, in which case Grype defaults apply for that scan. |

**`adaptive` is the default mode**: out of the box, kubevuln keeps its
no-false-negative posture for arbitrary images while trusted-vendor images
are matched against their vendor's authoritative feed.

Backward compatibility: the existing boolean keeps working and maps to
`off`/`on`; the new value wins if both are set.

### Per-scan decision

In `adaptive` mode, the Grype adapter consults the distro type it already
resolves at the top of each scan. If the type is in the trusted set, the
matcher configuration for **that scan only** is Grype's default
(`defaultMatcherConfig`); otherwise the CPE-enabled configuration is used,
exactly as today. Two existing functions are touched conceptually:
`getMatchers` gains awareness of the resolved distro, and the adapter carries
the mode instead of a boolean.

### Trust anchor: optional registry allowlist

`/etc/os-release` is self-declared, so the distro check alone can be spoofed:
any image could set `ID=echo` to receive lenient matching. To harden this,
adaptive mode supports an **optional registry allowlist** (e.g.
`reg.echohq.com/*`, `cgr.dev/*`). When an allowlist is configured, the
adaptive bypass triggers only if **both** the distro **and** the source
registry match; the distro alone is not enough.

The allowlist is **optional by design**. Leaving it unset preserves the
"private mirror" case, where an organization copies trusted-vendor images
(e.g. Chainguard) into an internal registry: those images still carry the
vendor's `/etc/os-release`, so distro-only matching keeps working for them.
Setting an allowlist is the stricter posture for environments that want the
registry to be an additional trust signal.

### Trusted vendor set

Initial set, mirroring what Grype itself recognizes as standalone
vendor-maintained distros with authoritative feeds:

- `echo` (Echo.ai)
- `chainguard` and `wolfi` (Chainguard)
- `minimos` (Minimus)

The set ships as a default but is overridable via configuration (helm value),
so onboarding the next vendor does not require a release.

### Observability

When the adaptive mode downgrades matching for a scan, the CVE manifest is
annotated (existing annotations mechanism) so that backend/UI can distinguish
"scanned with vendor-trusted matching" from a regular scan. This also gives
support a direct answer to "why do these two similar images show different
counts."

## Rollout

1. Verify Echo/Chainguard/Minimus feed coverage in the production Grype DB
   kubevuln consumes (see Open Questions #2); validate against `kafka-ui` and
   the packages from the reported false-positive list.
2. Land the three-mode config in kubevuln with `adaptive` as the default.
   Users who pinned the existing boolean keep their current behavior.

## Open questions (for team discussion)

1. **DB coverage verification.** The safety argument depends on the Echo
   provider actually being present in the Grype DB build we point kubevuln at
   (`ListingURL`). Needs a one-time verification and ideally a periodic check.
2. **Granularity of the trusted set.** Distro-type list only, or do we
   eventually want per-vendor knobs (e.g., trust Chainguard but not Echo)?
   The proposal assumes a flat list is enough.
3. **Stock matcher.** Even in Grype's default config the "stock" matcher uses
   CPEs (this is also upstream Grype behavior). Do we leave it as upstream
   does for trusted images, or align fully with the vendor-feed-only stance?

## References

- Kubevuln Grype adapter: `adapters/v1/grype.go` (`ScanSBOM`, `getMatchers`,
  `defaultMatcherConfig`)
- Kubevuln config: `config/config.go` (`UseDefaultMatchers`)
- Grype distro identification: `grype/distro/type.go` (`TypeFromRelease`,
  `IDMapping`)
