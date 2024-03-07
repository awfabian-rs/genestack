#!/bin/sh
GENESTACK_DIR=/Users/adam5637/Documents/git/ospc-flex/genestack
cd $GENESTACK_DIR/submodules/openstack-helm
helm template neutron ./neutron \
    --namespace=openstack \
    -f ../../helm-configs/neutron/neutron-helm-overrides.yaml \
    -f - \
    --post-renderer ../../kustomize/kustomize.sh \
    --post-renderer-args neutron/base << EOF  | gojq --yaml-input 'select(.metadata.name == "neutron-etc") | .data |= map_values(@base64d)' | grep -oE '216\.109\.154\.18[89]|8\.8\.8\.8|1\.1\.1\.1' | sort | uniq
conf:
  neutron:
    ovn:
      dns_servers: "216.109.154.188,216.109.154.189"
  plugins:
    ml2_conf:
      ovn:
        dns_servers: "216.109.154.188,216.109.154.189"
EOF
