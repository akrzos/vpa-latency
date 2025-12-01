#!/usr/bin/env bash

export KUBECONFIG=/root/vmno/kubeconfig

# Apply the VerticalPodAutoscalerController changes
# oc apply -f vpac.yml

nodes=$(oc get nodes -l node-role.kubernetes.io/worker= -o jsonpath='{.items[*].metadata.name}')

index=1
for node in $nodes; do
  echo "Labeling node $node as node-role.kubernetes.io/workload$index="
  oc label node $node node-role.kubernetes.io/workload$index=
  echo "Creating gohttp stress deployment for index $index"
  deployment_index=$index envsubst < deployments/gohttp-stress.yml.tmpl > deployments/gohttp-stress-$index.yml
  oc create -f deployments/gohttp-stress-$index.yml
  rm deployments/gohttp-stress-$index.yml
  index=$((index + 1))
done

# stress-ng pods where env vars control stressng sequence
# oc create -f deployments/1-underutil.yml
# oc create -f deployments/2-overutil.yml
# oc create -f deployments/3-standard.yml
# oc create -f deployments/4-longtermshift.yml
# oc create -f deployments/5-spike.yml
# oc create -f deployments/6-oom.yml
