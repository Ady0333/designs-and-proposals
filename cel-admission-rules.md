# CRD-Driven CEL Admission Rules in Operator

**Status:** Proposed
**Author:** Ben (ben@armosec.io)
**Date:** 2026-05-19

## Summary

Replace the Kubescape Operator's hardcoded admission rules (R2000 Exec-to-Pod,
R2001 Port-Forward) with CRD-defined rules evaluated via CEL — the same `Rules`
CRD schema the node-agent already uses for eBPF events, extended with a new
`k8s-admission` event type. The operator continues to run as a validating
admission webhook; rule matches generate alerts and never block the request.

## Motivation

Today, the operator's admission rules are static Go code. Adding a new rule
requires building and shipping a new operator image, even when the detection
logic is a single CEL expression. The node-agent already solves this for eBPF
events with the `Rules` CRD: rules are data, evaluated by a shared CEL engine,
hot-reloaded from the cluster. We want the same workflow for admission events.

Concretely:

- **Iterability** — Security engineers should be able to deploy a new detection
  by applying a YAML, no operator rebuild.
- **Schema parity** — One `Rules` CRD for both eBPF and admission domains.
  Node-agent ignores admission rules; operator ignores eBPF rules. The
  distinction is one field (`eventType`).
- **Consistency** — One CEL engine, one rule library, one binding model
  (`RuntimeAlertRuleBinding`) across the platform.

## Non-Goals

- **Blocking / enforcement** — This proposal is alert-only. A future enforcement
  mode is possible but out of scope. The validator never returns Forbidden.
- **Replacing node-agent rules** — The node-agent's eBPF rule path is untouched.
- **CEL feature parity with node-agent** — The operator's CEL environment ships
  with the K8s library and admission event model. Profile-dependent libraries
  (`ap.*`, `nn.*`) are node-agent-only.

## Architecture

```
                Kubernetes API server
                        |
                        | ValidatingWebhookConfiguration
                        v
            +---------- Operator ----------+
            |                              |
            |   AdmissionValidator         |
            |    1. self-pod short-circuit |
            |    2. kind-of-interest filter|
            |    3. enqueue (drop-on-full) |
            |    4. return nil (always)    |
            |                              |
            |          ↓ (channel)         |
            |                              |
            |   Worker pool (bounded)      |
            |    - resolve bindings        |
            |    - evaluate CEL            |
            |    - send alert via HTTP     |
            |                              |
            +------------------------------+
                        ^
                        |
              kubescape.io/v1 Rules CRD
              kubescape.io/v1 RuntimeAlertRuleBinding CRD
                        ^
                        |
                   RulesWatcher
                   RuleBindingCache
```

### Key components

- **`AdmissionCelEvent`** — Adapter that exposes `admission.Attributes` fields
  to CEL as `event.Kind`, `event.UserInfo`, `event.Operation`, etc., plus
  `object`/`oldObject`/`options` as top-level CEL variables.
- **`AdmissionCEL`** — The CEL engine: type registration via `ext.NativeTypes`,
  program cache, K8s library reused from node-agent.
- **`CelRuleEvaluator` / `CelRuleCreator`** — Implementations of the existing
  operator `RuleEvaluator` / `RuleCreator` interfaces, backed by live
  `RuntimeRule` CRD entries instead of compiled Go rules.
- **`RulesWatcher`** — Dynamic informer over `Rules` CRDs. Filters for enabled
  rules that have at least one `RuleExpression` with
  `EventType == "k8s-admission"`, then calls `CelRuleCreator.SyncRules`.
- **`AdmissionValidator`** — Webhook entry point. Becomes asynchronous (see
  below).

## Rule schema (no changes)

We reuse the existing `RuntimeRule` schema from `armoapi-go`. The only addition
is a new constant:

```go
EventTypeK8sAdmission EventType = "k8s-admission"
```

Example admission rule (CRD YAML):

```yaml
- name: "Exec to pod"
  id: "R2000"
  enabled: true
  description: "Detects exec operations on pods"
  expressions:
    message: "'Exec detected on pod: ' + event.Name + ' by ' + event.UserInfo.Username"
    uniqueId: "event.Namespace + '/' + event.Name"
    ruleExpression:
    - eventType: "k8s-admission"
      expression: 'event.Kind == "PodExecOptions"'
  severity: 8
  tags: ["exec", "admission"]
```

Bindings (`RuntimeAlertRuleBinding`) work unchanged — same selector model, same
ID/Name/Tags resolution.

## CEL event model

Scalar fields on the `event` variable:

| Field | Type | Source |
|-------|------|--------|
| `event.Kind` | string | `attrs.GetKind().Kind` |
| `event.Group` | string | `attrs.GetKind().Group` |
| `event.Version` | string | `attrs.GetKind().Version` |
| `event.Name` | string | `attrs.GetName()` |
| `event.Namespace` | string | `attrs.GetNamespace()` |
| `event.Operation` | string | `attrs.GetOperation()` |
| `event.Subresource` | string | `attrs.GetSubresource()` |
| `event.Resource` | string | `attrs.GetResource().Resource` |
| `event.UserInfo` | object | `.Username`, `.Groups`, `.UID` |
| `event.DryRun` | bool | `attrs.IsDryRun()` |

Object content (top-level CEL variables, not `event.object` — cel-go's
`ext.NativeTypes()` cannot expose `map[string]interface{}` struct fields):

| Variable | Description |
|----------|-------------|
| `object` | Full K8s resource (unstructured) |
| `oldObject` | Previous version on UPDATE |
| `options` | Operation options (e.g., PodExecOptions) |

## Performance and safety

A naive admission webhook is a foot-gun: every API write waits on it, and an
overloaded webhook can degrade the entire control plane. Three layers of
defense, applied in this order:

### 1. Self-pod short-circuit

The operator's own writes (status updates, leader election, alert export
retries) must not enter the rule pipeline. This is a hard guarantee against
positive feedback loops, not an optimization.

The validator drops any request where
`attrs.GetUserInfo().GetName() == operator's ServiceAccount` before any
further processing. The operator reads its own service account at startup
(from the projected token volume or downward API) and stores it on the
validator.

### 2. Kind-of-interest pre-filter

After a rule sync, `CelRuleCreator` extracts the set of `event.Kind == "X"`
patterns from all loaded rule expressions and exposes a
`KindsOfInterest() map[string]bool`. The validator checks this set before
enqueuing; non-matching kinds return immediately.

This is an optimization, not a correctness guarantee — rules with complex
expressions that don't pin a Kind will be matched by the `*` fallback. The
common case (most rules pin a Kind) gets the benefit.

### 3. Asynchronous evaluation with a bounded worker pool

The webhook is *synchronous from the API server's perspective* — but our
work doesn't have to be. The validator snapshots the request, enqueues onto
a buffered channel, and returns `nil` immediately. A small pool of worker
goroutines pulls from the channel and runs the full pipeline: binding
resolution, CEL evaluation, K8s enrichment, alert export.

| Parameter | Default | Notes |
|-----------|---------|-------|
| `workerPoolSize` | 10 | Bounded — never grows |
| `queueSize` | 1000 | Buffered channel capacity |
| Queue-full behavior | Drop with warning | Never block the API server |
| Drop counter | Prometheus metric | Operator drops alerts when overloaded; SREs must see this |

**Tradeoffs:**

- Alerts are best-effort. If the operator crashes mid-evaluation, the in-flight
  events are lost. Acceptable for alert-only mode; not acceptable for future
  enforcement.
- API requests get microsecond webhook latency regardless of rule complexity.
- A future enforcement mode would need a synchronous code path. Make it a
  config switch so the same validator can serve both modes.

### Webhook configuration

The `ValidatingWebhookConfiguration` keeps narrow `rules:` (specific GVRs and
operations we care about). We do *not* widen to `*` even with the protections
above — the API server's match logic is cheaper than ours, so let it filter
first.

`failurePolicy: Ignore` and a short `timeoutSeconds: 5` bound the worst-case
impact of an operator outage on cluster API latency.

## Rollout plan

Strict merge order across 4 repos:

| Order | Repo | Content |
|-------|------|---------|
| 1 | `armoapi-go` | `EventTypeK8sAdmission` constant *(merged: PR #649)* |
| 2 | `rulelibrary` | R2000 + R2001 as CEL YAML rules |
| 3 | `operator` | CEL engine, watcher, async validator, delete legacy rules |
| 4 | `helm-charts` | ClusterRole adds `rules` resource; webhook config covers networkpolicies; image bump after operator release |

## Validation

End-to-end test plan on a kind cluster (alert verified in operator logs):

- `kubectl exec` against a pod → R2000 fires
- `kubectl port-forward` → R2001 fires
- `kubectl apply -f networkpolicy.yaml` → R2002 fires
- Pod CREATE without matching rules → no alert
- Self-generated request (operator SA) → dropped, no log

All four scenarios validated against the locally built operator image.

## Open questions

- **Cooldown / dedup beyond rate limiting.** The exporter rate-limits to 100
  alerts/minute. The `UniqueID` CEL expression produces a dedup key but is not
  used for cooldown. Worth adding a fingerprint-based cooldown in the exporter
  before scaling.
- **Watcher cross-talk.** The dynamic watcher currently dispatches all events
  to all adaptors, so the RuleBindingCache receives Rules CRD events and logs
  a conversion error. The fix is a kind-filter inside each adaptor. Tracked in
  the operator PR.
- **Metrics surface.** Worker pool queue depth, drop counter, CEL evaluation
  duration, alert export latency — all should be Prometheus metrics. Not in
  the initial implementation; tracked as a follow-up.
