# F5 BIG-IP SNMP Monitoring

Genestack can poll an F5 BIG-IP HA pair with the OpenTelemetry Collector
Contrib SNMP receiver. The receiver is available for site overrides; it is
not enabled in the global base configuration.

## Placement and version

SNMP receivers belong in the centralized Deployment Collector. The node-local
DaemonSet must not poll infrastructure devices because every DaemonSet pod
would poll the same targets and remote-write duplicate series. A site that
enables F5 polling must keep the Deployment Collector at one replica unless it
also introduces explicit target sharding.

The `opentelemetry-kube-stack` chart is pinned at `0.13.1`; its operator
dependency supplies Collector version `0.141.0`. Genestack overrides only the
repository to select the Contrib distribution and inherits the tag from the
pinned chart. The core and Kubernetes distributions do not contain the SNMP
receiver. In Collector `0.141.0`, the SNMP receiver's metrics support is Alpha.
Treat a chart upgrade as a compatibility event and validate the resolved image
and receiver configuration before rollout.

Genestack's existing Helm values are the extension mechanism: a site override
adds named receivers, processors, environment variables, and service
pipelines under `collectors.deployment`. Helm merges mapping keys, but replaces
lists, so a site override that changes `deployment.env` or an existing pipeline
list must retain the base entries. A separate metrics pipeline per F5 member is
the simplest way to attach target-specific resource identity.

## Receiver contract

The initial scope intentionally collects one scalar:

| Item | Value |
| --- | --- |
| F5 object | `sysCmFailoverStatusId` |
| Scalar instance | `1.3.6.1.4.1.3375.2.1.14.3.1.0` |
| OTel metric | `f5.bigip.failover.state` |
| Prometheus metric | `f5_bigip_failover_state` |
| Type | Integer gauge |
| Values | `0` unknown, `1` offline, `2` forced offline, `3` standby, `4` active |

The supported Collector `0.141.0` syntax is `version: v3`,
`security_level: auth_priv`, `auth_type: SHA256`, and
`privacy_type: AES256`. Each endpoint must be a complete URI such as
`udp://f5-management.example:161`. DFW development polls every 60 seconds with
a 5-second timeout. This is deliberately narrow and leaves two polling
opportunities inside the two-minute warning window without placing an
aggressive load on the appliances.

The DFW override adds these stable, low-cardinality OTel resource attributes:

- `environment`
- `ha_pair`
- `device`

Prometheus Remote Write has `resource_to_telemetry_conversion` enabled, so the
expected Prometheus labels are `environment`, `ha_pair`, and `device`. The F5
pipelines intentionally omit the shared DFW `cluster` datapoint processor so
the metric identity remains small. Device identity is not derived from an IP
address.

## Secret contract

The DFW Deployment Collector references a Secret named `f5-bigip-snmp` in the
`monitoring` namespace. It must exist before Helm applies the Collector and
must contain these keys:

| Key | Content |
| --- | --- |
| `username` | Current SNMPv3 user |
| `auth-password` | SNMPv3 authentication password |
| `privacy-password` | SNMPv3 privacy password |

No Secret manifest or credential value is stored in Git. The non-sensitive
management endpoints, stable device names, and HA-pair identity belong in the
site-specific Collector override under `/etc/genestack`, not in this Secret or
the reusable Genestack base configuration. The historical username `FLEXMON`
remains informational until operations confirms the current credential.

One safe creation pattern uses protected files and never prints their values:

```shell
kubectl -n monitoring create secret generic f5-bigip-snmp \
  --from-file=username=/secure/f5-snmp/username \
  --from-file=auth-password=/secure/f5-snmp/auth-password \
  --from-file=privacy-password=/secure/f5-snmp/privacy-password \
  --dry-run=client -o yaml | kubectl apply -f -
```

Protect the source files, delete them securely according to the site's secret
handling policy, and never inspect the Secret with a command that decodes or
prints its data.

## Poll health

Prometheus does not scrape the F5s and therefore has no exporter-style `up`
series for an SNMP poll. The Deployment Collector's ServiceMonitor instead
exposes this scraper-helper counter directly to Prometheus:

```promql
otelcol_scraper_scraped_metric_points_total{
  receiver=~"snmp/f5-.+",
  scraper="snmp"
}
```

Collector `0.141.0` retains the full named receiver ID in `receiver`, creates
the counter even when a scrape yields zero points, and increments it for each
successfully produced metric point. A flat counter therefore distinguishes a
reachable F5 reporting state 0, 1, or 2 from a poll that produces no telemetry.
The counter survives a Remote Write outage because Prometheus scrapes Collector
self-telemetry directly. `increase()` handles Collector counter resets.

The F5 rules do not include generic Collector-down or Prometheus Remote Write
failure alerts. If the complete Deployment Collector is down, its ServiceMonitor
is absent, or a receiver is removed from configuration, the scraper counter
disappears and cannot identify the expected target. A Remote Write failure can
also prevent the state metric from reaching Prometheus while this directly
scraped counter continues to increase. Those stack-wide conditions need
separately owned platform alerts. The next F5-specific improvement, once a
source-controlled target inventory exists, is an expected-target info metric
that can alert on a missing receiver definition.

## Operational controls

- Keep the initial scope to the one failover scalar and two receivers.
- Keep the stack chart pinned; verify its resolved Contrib Collector image on
  every chart update.
- Keep exactly one Deployment Collector replica unless polling is sharded.
- Permit outbound UDP/161 from the Deployment Collector pod network and add
  that source network to the F5 SNMP allowlist.
- Provide separately owned platform alerts for Collector availability and
  Prometheus Remote Write failures; the F5 policy monitors per-receiver progress.
- Validate component availability and configuration on every Collector upgrade.
- Roll back by reverting the site override and rules; do not reintroduce
  `prometheus-snmp-exporter`.

See the DFW-development override repository for environment-specific rendering,
deployment, query, and fault-injection validation commands.
