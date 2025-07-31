#!/usr/bin/env bash

export KUBECONFIG=/root/vmno/kubeconfig

# Apply the VerticalPodAutoscalerController changes
oc apply -f vpac.yml

# Label the worker nodes each for a different workload
oc label no vm00004 node-role.kubernetes.io/workload1=
oc label no vm00005 node-role.kubernetes.io/workload2=
oc label no vm00006 node-role.kubernetes.io/workload3=
oc label no vm00007 node-role.kubernetes.io/workload4=
oc label no vm00008 node-role.kubernetes.io/workload5=
oc label no vm00009 node-role.kubernetes.io/workload6=
oc label no vm00010 node-role.kubernetes.io/workload7=
oc label no vm00011 node-role.kubernetes.io/workload8=
oc label no vm00012 node-role.kubernetes.io/workload9=

# Create the vpa-stress namespaces and deployments
oc create -f deployments/1-gohttp-stress.yml
# oc create -f deployments/1-underutil.yml
# oc create -f deployments/2-overutil.yml
# oc create -f deployments/3-standard.yml
# oc create -f deployments/4-longtermshift.yml
# oc create -f deployments/5-spike.yml
# oc create -f deployments/6-oom.yml
