#!/usr/bin/env bash

export KUBECONFIG=/root/vmno/kubeconfig

# Namespace prefix for the gohttp stress deployments
namespace_prefix=vpa-gohttp-stress

measurement_time=300
initial_api_wait=60
stress_memory=20
stress_timeout=120

# 5s sleep time for 12 nodes (60s / 12 nodes = 5s between runs)
sleep_time=5

nodes=$(oc get nodes -l node-role.kubernetes.io/worker= -o jsonpath='{.items[*].metadata.name}')

index=1
for node in $nodes; do
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Starting ${namespace_prefix}-${index} on node ${node}"
  ./vpa-latency.py -m ${measurement_time} -i ${initial_api_wait} -s ${stress_memory} -t ${stress_timeout} -p 1 -n ${namespace_prefix}-${index} 2> results/${namespace_prefix}-${index}.log &
  sleep ${sleep_time}
  index=$((index + 1))
done

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) All deployments started, waiting for completion..."
wait $(jobs -p)
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) All deployments completed"
