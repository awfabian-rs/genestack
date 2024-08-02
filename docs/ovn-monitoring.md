# Background

- This page describes OVN monitoring in _Genestack_.
- Most OVN monitoring in _Genestack_ comes from _Kube-OVN_'s model
    - As the _Kube-OVN_ documentation indicates, this includes both:
        - control plane information
        - data plane network quality information
    - _Kube-OVN_ has
     [instrumention](https://prometheus.io/docs/practices/instrumentation/)
     for _Promethus_
        - so _Genestack_ documentation directs installing the k8s _ServiceMonitors_
          so that _Promethus_ can discover these metrics.

## Links

- [_Genestack_ documentation on installing _Kube-OVN_ monitoring](./prometheus-kube-ovn.md)
  - As mentioned above, this simply installs the _ServiceMonitors_ so that
    _Prometheus_ in _Genestack_ can discover the metrics exported by _Kube-OVN_.
  - you can see the _ServiceMonitors_ installed
    [here](https://github.com/rackerlabs/genestack/tree/main/base-kustomize/prometheus-ovn)
        - in particular, it has _ServiceMonitors_ for components:
            - _kube-ovn-cni_
            - _kube-ovn-controller_
            - _kube-ovn-monitor_
            - _kube-ovn-pinger_

            You can see a architectural descriptions of these components
            [here](https://kubeovn.github.io/docs/stable/en/reference/architecture/#core-controller-and-agent)

- [_Kube-OVN User Guide's "Monitor and Dashboard"_ section](https://kubeovn.github.io/docs/stable/en/guide/prometheus-grafana/)
    - the information runs a bit sparse in the User Guide; note the reference
      manual link (in the User Guide itself, and next link here below) for more
      detailed information on the provided metrics.
- [_Kube-OVN Reference Manual "Metrics"_](https://kubeovn.github.io/docs/stable/en/reference/metrics/)
    - This describes the monitoring metrics provided by _Kube-OVN_

# Metrics

## Viewing the metrics

In a full _Genestack_ installation, you can view Prometheus metrics:

- by querying _Prometheus_' HTTPS API
- by using _Prometheus_' UI
- by using _Grafana_
    - In particular, _Kube-OVN_ provides pre-defined Grafana dashboards
      installed in _Genestack_.

Going in-depth on these would go beyond the scope of this document, but sections
below provide some brief coverage.

### Prometheus' data model

_Prometheus_' data model and design-for-scale tends to make interactive
[_PromQL_](https://prometheus.io/docs/prometheus/latest/querying/basics/)
queries cumbersome. In general usage, you will find that _Prometheus_ data works
better for feeding into other tools, like the _Alertmanager_ for alerting, and
_Grafana_ for visualization.

### Prometheus UI

A full _Genestack_ installation includes the _Prometheus UI_. The _Prometheus_
UI prominently displays a search bar that takes _PromQL_ expressions.

You can easily see the available _Kube-OVN_ metrics by opening the Wetrics
Explorer (click the globe icon) and typing `kube_ovn_`.

While this has some limited utility for getting a low-level view of individual
metrics, you will generally find it more useful to look at the Grafana
dashboards as described below.

As mentioned above, the _Kube-OVN_ documentation details the collected metrics
[here](https://kubeovn.github.io/docs/stable/en/reference/metrics)
