#!/usr/bin/env bash

export KUBECONFIG=/root/vmno/kubeconfig

# Namespace prefix for the gohttp stress deployments
export namespace_prefix=vpa-gohttp-stress1

nodes=$(oc get nodes -l node-role.kubernetes.io/worker= -o jsonpath='{.items[*].metadata.name}')

index=1
for node in $nodes; do
  echo "Labeling node $node as node-role.kubernetes.io/workload$index="
  oc label node $node node-role.kubernetes.io/workload$index=
  echo "Creating gohttp stress deployment for index $index"
  deployment_index=$index envsubst < manifests/gohttp-stress.yml.tmpl > manifests/gohttp-stress-$index.yml
  oc create -f manifests/gohttp-stress-$index.yml
  rm manifests/gohttp-stress-$index.yml
  index=$((index + 1))
done
