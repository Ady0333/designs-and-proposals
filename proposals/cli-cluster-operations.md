# Proposal: Kubescape CLI Control Over Cluster Operations

- **Status:** Draft
- **Related issues:**
  - [kubescape/kubescape#1770: Kubescape CLI control over cluster operations](https://github.com/kubescape/kubescape/issues/1770) (open)
- **Scope:** [`kubescape`](https://github.com/kubescape/kubescape) CLI, [`operator`](https://github.com/kubescape/operator), [`armoapi-go`](https://github.com/armosec/armoapi-go), [`helm-charts`](https://github.com/kubescape/helm-charts); [`headlamp-plugin`](https://github.com/kubescape/headlamp-plugin) + [`kubescape.io`](https://github.com/kubescape/kubescape.io) (phased)
- **Author:** Yugal Sadhwani (<yashsadhwani544@gmail.com>)

## Summary

Issue #1770 ("Kubescape CLI control over cluster operations") is currently an
empty roadmap stub. The discussion on the issue has since converged on a
concrete need: the ability to **act on scan findings from the CLI** (and,
optionally, automatically from within the cluster) rather than manually piping
`kubescape scan` output into `kubectl` commands to quarantine or cordon
resources.

This proposal does two things:

1. Defines a small, **extensible "operator action" command framework** that lets
   the Kubescape CLI ask the in-cluster operator to perform cluster operations,
   building on the command pipeline that already powers `kubescape operator
   scan`.
2. Implements the **first concrete action set: post-scan remediation**
   (`quarantine`, `cordon`, `annotate`) with **dry-run as the default**, driven
   by findings already stored in the cluster.

The operator remains the **sole executor** of any cluster mutation; the CLI is a
thin client. The same `Command` contract is reused both for CLI-triggered
actions and for an optional operator-native auto-remediation loop, which means
the "CLI subcommand vs. operator-native action" question raised in the issue is
answered as **both, over one shared contract**.

## Motivation

From the issue thread (@kunalworldwide's use cases):

- **CI gate**: run `kubescape scan` in CI and act on critical findings instead
  of just reporting them.
- **Scheduled in-cluster response**: periodic scans that auto-quarantine
  non-compliant workloads in system namespaces.
- **Incident response**: cordon a node showing Indicators of Compromise.

Today there is no built-in "scan → do something about it" path. Users wrap the
CLI in custom scripts that parse results and call `kubectl` by hand. This is
error-prone, has no dry-run/preview, no audit trail, and no consistent safety
rails.

The good news, established by reading the code, is that **the plumbing to send
an instruction from the CLI to the cluster already exists**: it is used for
`kubescape operator scan configurations|vulnerabilities`. Remediation is, at the
architectural level, a new verb on that existing pipeline.

## Goals

- Define an extensible mechanism for the CLI to trigger cluster operations via
  the operator, reusing the existing `apis.Commands` pipeline.
- Ship a first remediation action set: **quarantine workload**, **cordon node**,
  **annotate/label** (all reversible where possible).
- **Dry-run by default**: every action previews its effect (using Kubernetes
  server-side dry-run) and requires explicit confirmation to apply.
- Drive remediation from **findings already stored in-cluster** (the
  `spdx.softwarecomposition.kubescape.io` scan-result CRDs), no re-scan required.
- Keep all destructive capability **opt-in** at install time (Helm flag + scoped
  RBAC); the default install gains no new mutating powers.
- Provide an **audit trail** (Kubernetes Events + `OperatorCommand` CRD status).
- Allow the same action to be triggered **automatically** from the operator's
  continuous-scanning loop (phase 3), gated by policy.

## Non-Goals

- Replacing admission control / policy enforcement (Kyverso / VAP / the existing
  admission webhook). Remediation here is *reactive*, post-scan, not an admission
  gate.
- A general-purpose `kubectl` replacement. The action set is a curated,
  security-motivated list, not arbitrary cluster control.
- Cross-cluster / fleet orchestration.
- Auto-remediation **on by default**. Auto mode is opt-in and ships last.

## Proposal

### The existing pipeline we build on

```
kubescape CLI                                    operator (in-cluster)
─────────────                                    ─────────────────────
cmd/operator/operator.go                         restapihandler/restapi.go
  (arg validation + subcommand routing)            route POST /v1/triggerAction
        │                                                │
core/cautils/operatorscaninfo.go                 restapihandler/triggeraction.go
  IOperatorScanInfo.GetRequestPayload()            HandleActionRequest()
   → builds *apis.Commands                         → ants worker pool
        │                                                │
core/core/clusterconnector.go                    mainhandler/handlerequests.go
  OperatorAdapter.OperatorScan() ──HTTPS POST──▶    handleRequest()
   → httpPostOperatorScanRequest()                  switch CommandName { … } ← dispatch
   → operatorTriggerPath ("v1/triggerAction")
```

The command contract (`armoapi-go/apis/websocketdatastructures.go`):

```go
type Command struct {
    CommandName NotificationPolicyType        // verb, e.g. "kubescapeScan"
    Args        map[string]interface{}        // free-form action params
    Designators []identifiers.PortalDesignator
    Wlid        string                        // workload id
    WildWlid    string                        // wildcard workload id
    // …
}
```

Verb constants live in `armoapi-go/apis/clusterapis.go`
(`TypeRunKubescape = "kubescapeScan"`, `TypeScanImages = "scan"`, … at lines
22–55). Adding a cluster operation is therefore: **a new constant + a new `case`
in the operator dispatch switch + a new CLI subcommand.**

There is also a second, status-returning delivery channel for the *same*
`Command`: the **`OperatorCommand` CRD** (`kubescape.io/operatorcommands` with a
`/status` subresource), watched by `watcher.NewOperatorCommandsHandler`. This is
the GitOps- and Headlamp-friendly path and is how we surface dry-run plans and
audit results.

#### Delivery Pipeline Decoupling: Standalone vs. Connected

Because Kubescape can be deployed in a variety of environments, this design cleanly supports two distinct command delivery pathways:

1. **Standalone OSS Path (No Synchronizer)**:
   * **Direct Trigger**: The Kubescape CLI issues a direct HTTPS POST request containing the `apis.Command` payload to the operator's local REST endpoint `/v1/triggerAction` (typically exposed via `kubectl port-forward`). No CRD or Synchronizer is involved.
   * **GitOps Trigger**: Users apply `OperatorCommand` CRD resources directly to the Kubernetes API using `kubectl apply` or a GitOps engine (like ArgoCD). The operator watches these local resources directly via its watch handler and executes them locally.
2. **Connected Commercial Path (With Synchronizer)**:
   * The ARMO backend runs outside the cluster's firewall and cannot call the operator's REST API directly. Instead, it uses the **Synchronizer** as a secure proxy.
   * When an action is triggered via the ARMO Dashboard, the backend marshals the `apis.Command`, encodes it, and wraps it in a `v1alpha1.OperatorCommand` custom resource with `Spec.CommandType` set to `OperatorCommandTypeOperatorAPI`. It pushes this command down via Pulsar (`synchronizer-in-topic`).
   * The in-cluster synchronizer component receives this payload and writes the `OperatorCommand` CRD directly to the cluster's local Kubernetes API.
   * The operator watches and processes the CRD exactly as it would in the standalone GitOps path.
   * The in-cluster synchronizer watches the CRD status and relays the execution progress back to the backend.

This architectural split keeps the core operator logic completely standalone and decoupled from backend microservices or Synchronizer requirements, while remaining 100% compatible when they are present.

### Layer 1: the action framework

Introduce a generic action verb:

```go
// armoapi-go/apis/clusterapis.go
TypeOperatorAction NotificationPolicyType = "operatorAction"
```

`Command.Args` for an action:

```jsonc
{
  "action":     "quarantine",        // quarantine | cordon | annotate | revert
  "target":     { "kind": "Deployment", "namespace": "payments", "name": "api" },
  "selector":   { "control": "C-0016", "minSeverity": "High" }, // findings-driven
  "findingRef": "workloadconfigurationscansummaries/payments/api",
  "dryRun":     true,                 // DEFAULT true
  "ttl":        "24h",                // optional auto-revert
  "reason":     "C-0016 allowPrivilegeEscalation"
}
```

The operator dispatches `TypeOperatorAction` to a new
`mainhandler/actionhandler.go`, which routes on `Args["action"]` to individual
`Remediator` implementations. New actions = new `Remediator`, no pipeline
changes.

```go
type Remediator interface {
    // Plan computes the intended changes without applying them.
    Plan(ctx context.Context, t Target) (Plan, error)
    // Apply executes the plan; honors server-side dry-run.
    Apply(ctx context.Context, p Plan, dryRun bool) (Result, error)
    // Revert undoes a previously applied action.
    Revert(ctx context.Context, t Target) (Result, error)
}
```

### Layer 2: remediation v1 (the first actions)

| Action | What it does | Reversible | RBAC needed |
|--------|--------------|-----------|-------------|
| `annotate` | Add label/annotation (`kubescape.io/quarantine=true`, finding ref) | yes | `apps` deployments `patch`, core pods `patch` |
| `quarantine` | Deny-all `NetworkPolicy` + quarantine label (optionally scale to 0) | yes | + `networking.k8s.io` networkpolicies `create/delete` |
| `cordon` | `node.Spec.Unschedulable=true` (+ optional taint) | yes (`revert`/uncordon) | + core nodes `patch` |

Targeting is **findings-driven**: the handler reads the relevant stored
scan-result CRD: `workloadconfigurationscansummaries` /
`vulnerabilitymanifestsummaries` (the operator already has `get/watch/list` on
the `spdx.softwarecomposition.kubescape.io` group), to resolve "workloads
failing control X / with ≥ High severity" into a concrete target set.

### Layer 3: operator-native auto-remediation (last phase)

The continuous-scanning service (`operator/continuousscanning/service.go`)
exposes pluggable `EventHandler`s. We add an opt-in `remediationEventHandler`
that, on a new finding crossing a configured threshold, emits the **same**
`TypeOperatorAction` command (defaulting to dry-run unless auto-apply is
explicitly enabled in operator config). This reuses Layer 1/2 entirely.

### User Stories

#### Story 1: CI preview then apply

```bash
# In CI: see what would be quarantined for a failing control, no changes made
kubescape operator remediate quarantine --control C-0016 --min-severity High
# → prints a plan (server-side-dry-run validated), exits non-zero if plan non-empty

# Gated apply step (manual approval in the pipeline)
kubescape operator remediate quarantine --control C-0016 --min-severity High --confirm
```

#### Story 2: Incident response, cordon a node

```bash
kubescape operator remediate cordon --node ip-10-0-3-7 --reason "runtime IoC"            # dry-run
kubescape operator remediate cordon --node ip-10-0-3-7 --reason "runtime IoC" --confirm  # apply
kubescape operator remediate revert --node ip-10-0-3-7                                    # uncordon
```

#### Story 3: Scheduled in-cluster auto-quarantine (opt-in)

Operator config enables `remediation.auto` with a namespace allow-list and a
severity threshold; the continuous-scanning loop quarantines newly
non-compliant workloads in those namespaces and records each action on an
`OperatorCommand` CRD for audit.

### Issue coverage

Issue #1770 itself is an empty roadmap stub; the concrete requirements come from
@kunalworldwide's comments (which @matthyx explicitly asked him to enumerate).
This proposal answers the **discussion-converged** need (post-scan remediation)
rather than the literal open-ended title; broad, arbitrary "cluster operations"
are fenced off in [Non-Goals](#non-goals) by design.

| Requirement from the thread | Where addressed | Status |
|---|---|---|
| Replace wrapper scripts that `scan` then hand-feed failed resources into `kubectl` to quarantine | `quarantine` action + findings-driven targeting (reads `workloadconfigurationscansummaries`) | done |
| Dry-run before any real mutation ("especially in prod") | [Dry-run semantics](#dry-run-semantics): default-on, CLI plan + server-side `DryRunAll`; only `--confirm` writes | done |
| Scenario 1: CI pipeline blocking deploys on critical findings | Story 1 (plan, non-zero exit, gated `--confirm`) | done |
| Scenario 2: scheduled in-cluster scans auto-quarantine non-compliant namespaces | Story 3 / Layer 3 `remediationEventHandler` + namespace allow-list | done |
| Scenario 3: operator cordons a node showing Indicators of Compromise | Story 2 (`remediate cordon`), **manual only** | partial |
| "CLI `remediate` subcommand or operator-native action?" | Answered: **both, over one shared `Command` contract** | done |
| "Needs a webhook/callback since the scan flow only posts results" | Plumbing already exists (`triggerAction` pipeline + `OperatorCommand` status channel); no new webhook needed | done |

**IoC-cordon caveat (scenario 3).** Indicators of Compromise are produced by the
**runtime** detection stream (node-agent, e.g. `runtimerulealertbindings`), not the
posture/config/vuln scan-result CRDs that the findings-driven targeting and the
Layer 3 auto loop read. So *manual* cordon is fully covered, but **automatic**
"node shows IoC -> cordon" would require wiring the Layer 3 `EventHandler` to the
runtime-alert stream. That is intentionally **out of scope for the phases above**
(auto-cordoning nodes off raw runtime signals is high blast-radius) and is noted
here as a candidate later phase rather than a covered case.

## Design Details

### CLI surface (`kubescape` repo)

- `cmd/operator/operator.go`: extend to accept the `remediate` subcommand
  (currently it hard-rejects anything but `scan`).
- `cmd/operator/remediate.go` (new): `remediate quarantine|cordon|annotate|revert`
  with flags: `--dry-run` (default `true`), `--confirm`, `--control`,
  `--min-severity`, `--namespace`, `--node`, `--wlid`, `--ttl`, `--reason`.
- `core/cautils`: a `RemediationInfo` struct mirroring `OperatorInfo`.
- Reuse the existing transport in `core/core/clusterconnector.go`
  (`OperatorAdapter.OperatorScan` / `httpPostOperatorScanRequest`, which POSTs an
  `apis.Commands` payload to `operatorTriggerPath = "v1/triggerAction"`); the
  payload is assembled via the `IOperatorScanInfo.GetRequestPayload() *apis.Commands`
  pattern in `core/cautils/operatorscaninfo.go`: no new transport code.

### Operator surface (`operator` repo)

- `mainhandler/handlerequests.go`: add `case apis.TypeOperatorAction:` to the
  `handleRequest` switch.
- `mainhandler/actionhandler.go` (new): `Remediator` registry + dispatch on
  `Args["action"]`.
- `mainhandler/remediators/*.go` (new): `annotate`, `quarantine`, `cordon`.
- `continuousscanning/`: optional `remediationEventHandler` (phase 3).
- Write progress/result and the **dry-run plan** back to the `OperatorCommand`
  CRD status; emit a Kubernetes `Event` per action.

### API surface (`armoapi-go` repo)

- New `TypeOperatorAction` constant + documented `Args` schema (above).

### Dry-run semantics

Two layers, both on by default:

1. **CLI default**: `--dry-run=true`; the operator only computes and returns the
   plan (target list + diffs) without mutating.
2. **Server-side dry-run**: when validating a plan, the operator issues the
   mutation with `metav1.*Options{DryRun: []string{metav1.DryRunAll}}` so it is
   checked against admission controllers without persisting.

Only `--confirm` (equivalently `dryRun=false`) performs a real write.

### RBAC & install (`helm-charts` repo)

The operator ClusterRole
(`charts/kubescape-operator/templates/operator/clusterrole.yaml`) is currently
**read-only** on `pods/nodes/namespaces` and has **no `networkpolicies`**. Add a
new rule block **gated behind a `capabilities.remediation` value** (default
`disable`), so the default install gains nothing:

```yaml
{{- if eq .Values.capabilities.remediation "enable" }}
- apiGroups: ["apps"]
  resources: ["deployments","statefulsets","daemonsets"]
  verbs: ["patch"]
- apiGroups: [""]
  resources: ["pods","nodes","namespaces"]
  verbs: ["patch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["create","delete","get","list"]
{{- end }}
```

### Safety rails

- Dry-run default + explicit `--confirm`.
- **Namespace allow/deny list** in operator config; protected namespaces
  (`kube-system`, the kubescape namespace) denied by default.
- Required severity/control threshold: no "remediate everything".
- TTL / auto-revert and an explicit `revert` action.
- Full audit trail via `OperatorCommand` status + Kubernetes Events.
- Auto mode (Layer 3) additionally requires `remediation.auto=enable`.

### Phasing

| Phase | Deliverable |
|-------|-------------|
| 0 | This design doc + issue comment; agree the CLI-vs-operator framing |
| 1 | Command plumbing end-to-end with `annotate` only + dry-run (CLI → operator → `OperatorCommand` status). Proves the pipeline, ~zero blast radius |
| 2 | `quarantine` (NetworkPolicy + label), findings-driven targeting, RBAC + Helm flag, `revert` |
| 3 | `cordon`, operator-native auto-remediation `EventHandler`, TTL/auto-revert |
| 4 (opt) | Headlamp UI to preview/trigger via the `OperatorCommand` CRD; docs in `kubescape.io` |

## Alternatives

- **CLI mutates the cluster directly (kubectl-style).** Rejected: duplicates
  RBAC the operator already holds, bypasses the audit/status channel, and gives
  the action no in-cluster home for auto mode.
- **Operator-native only (no CLI).** Rejected: loses the CI/incident-response
  interactive flow that motivated the issue; the CLI surface is explicitly what
  #1770 asks for.
- **Bespoke remediation API/endpoint.** Rejected: the `apis.Commands` pipeline +
  `OperatorCommand` CRD already provide transport, queuing, and status; a new
  endpoint would reinvent them.
- **Reuse the admission webhook for enforcement.** Complementary, not a
  substitute: that path blocks *new* objects; this path responds to findings on
  *existing* running workloads/nodes.

## Production Readiness / Risks

- **Blast radius of a bad remediation.** Mitigated by dry-run default, server-side
  dry-run validation, namespace deny-list, severity thresholds, reversibility,
  and TTL auto-revert.
- **Privilege escalation surface.** New mutating RBAC is opt-in via Helm and
  scoped to the specific resources/verbs each action needs.
- **Stale findings.** Targeting reads stored scan-result CRDs, which may lag a
  live scan; document that auto mode should be paired with a reasonable scan
  cadence, and record the `findingRef` (and its timestamp) on every action.
- **Auditability.** Every action writes `OperatorCommand` status + a Kubernetes
  Event with the justifying finding.

## Alignment with ARMO Runtime Incident Processing

To ensure seamless alignment with ARMO's commercial platform (described in [Runtime Incident/Alert Processing](https://github.com/armosec/shared-designs-and-docs/blob/main/runtime-backend/runtime-incident-processing.md) and implemented in the [event-ingester-service](https://github.com/armosec/event-ingester-service)), this design bridges the open-source operator capabilities and the commercial incident response pipeline:

1. **Pipeline Coexistence**:
   * **OSS (Decentralized/Local, No Synchronizer)**:
     * In a pure OSS setting, the Synchronizer is absent.
     * The CLI interacts directly with the operator's REST API `/v1/triggerAction` to execute commands.
     * Alternatively, local GitOps loops write `OperatorCommand` CRDs directly to the Kubernetes API, which the operator watches and executes locally.
   * **Commercial (SaaS/Centralized, With Synchronizer)**:
     * The ARMO backend (`event-ingester-service`) executes advanced, traffic-aware NetworkPolicy or Seccomp profile generation and pushes these generated manifests directly to the cluster via the Synchronizer.
     * For active response commands (`Kill`, `Pause`, `Stop`), the backend writes an `OperatorCommand` CRD (wrapped in a Synchronizer message) and relays it through the Pulsar-to-Synchronizer proxy, which applies the CRD to the local Kubernetes API.
     * The operator watches and processes the CRD exactly like an OSS GitOps flow, keeping the core operator completely decoupled from backend/Pulsar logic.
   * These two mechanisms are fully complementary. The extensible `operatorAction` framework allows the OSS operator to execute local mutations, while leaving the backend free to invoke advanced or process-level responses.

2. **Common Audit Tracking**: Since both paths write state and results back to the `OperatorCommand` CRD status and emit Kubernetes Events, the ARMO backend's synchronizer will automatically pick up the status transitions (`initiated`, `applied`, `failed`) and write them to the commercial audit log (`v1_audit_log`) and SIEM stream without polling.

3. **Active Response Evolution**: The extensible action registry in `mainhandler/actionhandler.go` is designed to seamlessly adopt process-level active response verbs (`kill`, `pause`, `stop`) in future phases to align with the core `kdr.ResponseType` actions supported in the ARMO commercial platform.

## Resolved Open Questions

1. **Action verb naming: single `operatorAction` + `Args.action` (proposed) vs. one `CommandName` per action (`quarantineWorkload`, `cordonNode`)?**
   * **Resolved**: Keep the single generic `operatorAction` with `Args.action` parameter. This matches the generic `apis.Command` payload architecture, provides maximum extensibility for future active response verbs (like `kill`, `pause`, `stop`), and avoids repeated modifications to the core communication schemas.

2. **Where should the namespace allow/deny list and severity thresholds live: operator `config` ConfigMap, Helm values, or a dedicated `RemediationPolicy` CRD?**
   * **Resolved**: Helm values/ConfigMap for Phase 1 (bootstrap and simple local setups), transitioning to standard Policy configuration blocks in subsequent phases. Storing the rules in a structured configuration schema allows the rules to align with ARMO's `IncidentPolicy` scopes (reusing standard label selectors and namespace targets).

3. **Should `quarantine` default to deny-all NetworkPolicy, scale-to-0, or be explicitly chosen per invocation?**
   * **Resolved**: Default to a non-destructive deny-all NetworkPolicy. In security incident response, preserving container state is critical for forensic investigation (e.g., memory and process trees). Scaling to zero destroys the container, wiping out all forensic evidence. Scaling to zero or container stopping should be an explicit opt-in parameter (like `quarantineMode: scaleToZero` or a separate `stop` action) rather than the default.
