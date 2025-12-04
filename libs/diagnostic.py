#!/usr/bin/env python3
#  Copyright 2025 Red Hat
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import json
import sys
from libs.command import command
import logging
import os

logger = logging.getLogger("vpa-latency")


def oc_gather(verb, resource, namespace, diagnostic_data_dir, file_name, cmd_out=None):
  cmd = ["oc", verb, resource, "-n", namespace]
  if cmd_out is not None:
    cmd.extend(["-o", cmd_out])
  rc, output = command(cmd, retries=3, no_log=True)
  if rc != 0:
    logger.error(f"vpa-latency, oc {verb} {resource} rc: {rc}")
  else:
    with open(os.path.join(diagnostic_data_dir, file_name), "w") as f:
      f.write(output)


def gather_diagnostic_data(cliargs, report_dir, diagnostic_dir):

  rc, output = command(["oc", "get", "po", "-n", cliargs.namespace, "-o", "json"], retries=3, no_log=True)
  if rc != 0:
    logger.error("vpa-latency, oc get po rc: {}".format(rc))
  else:
    try:
      po_data = json.loads(output)
    except json.decoder.JSONDecodeError:
      logger.error("vpa-latency, po JSONDecodeError: {}".format(output[:2500]))
    
  diagnostic_data_dir = os.path.join(report_dir, diagnostic_dir)
  os.mkdir(diagnostic_data_dir)

  # Get the VPAC
  if diagnostic_dir == "post-test":
    oc_gather("get", "VerticalPodAutoscalerController", "openshift-vertical-pod-autoscaler", diagnostic_data_dir, "VerticalPodAutoscalerController.yaml", "yaml")

  # Get and describe the VPA
  oc_gather("get", "vpa", cliargs.namespace, diagnostic_data_dir, "vpa")
  oc_gather("get", "vpa", cliargs.namespace, diagnostic_data_dir, "vpa.yaml", "yaml")
  oc_gather("describe", "vpa", cliargs.namespace, diagnostic_data_dir, "vpa.describe")

  # Get and describe the pods for monitored namespace
  oc_gather("get", "po", cliargs.namespace, diagnostic_data_dir, "pods.{}".format(cliargs.namespace))
  oc_gather("get", "po", cliargs.namespace, diagnostic_data_dir, "pods.{}.yaml".format(cliargs.namespace), "yaml")
  oc_gather("describe", "po", cliargs.namespace, diagnostic_data_dir, "pods.{}.describe".format(cliargs.namespace))

  # Get and describe the pods for VPA operator namespace
  oc_gather("get", "po", "openshift-vertical-pod-autoscaler", diagnostic_data_dir, "pods.openshift-vertical-pod-autoscaler")
  oc_gather("get", "po", "openshift-vertical-pod-autoscaler", diagnostic_data_dir, "pods.openshift-vertical-pod-autoscaler.yaml", "yaml")
  oc_gather("describe", "po", "openshift-vertical-pod-autoscaler", diagnostic_data_dir, "pods.openshift-vertical-pod-autoscaler.describe")

  # Get and describe the deployments
  oc_gather("get", "deploy", cliargs.namespace, diagnostic_data_dir, "deployments.{}".format(cliargs.namespace))
  oc_gather("get", "deploy", cliargs.namespace, diagnostic_data_dir, "deployments.{}.yaml".format(cliargs.namespace), "yaml")
  oc_gather("describe", "deploy", cliargs.namespace, diagnostic_data_dir, "deployments.{}.describe".format(cliargs.namespace))

  # Get the logs for the pods
  for pod in po_data["items"]:
    rc, output = command(["oc", "logs", "-n", cliargs.namespace, pod["metadata"]["name"]], retries=3, no_log=True)
    if rc != 0:
      logger.error("vpa-latency, oc logs rc: {}".format(rc))
    with open(os.path.join(diagnostic_data_dir, "{}.log".format(pod["metadata"]["name"])), "w") as f:
      f.write(output)
    if diagnostic_dir == "post-test":
      rc, output = command(["oc", "logs", "-n", cliargs.namespace, pod["metadata"]["name"], "-p"], retries=3, no_log=True)
      if rc != 0:
        logger.error("vpa-latency, oc logs rc: {}".format(rc))
      with open(os.path.join(diagnostic_data_dir, "{}.previous.log".format(pod["metadata"]["name"])), "w") as f:
        f.write(output)
