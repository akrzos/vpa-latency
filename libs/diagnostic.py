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


def oc_gather(verb, resource, namespace, diagnostic_data_dir, output=None):
  if output is None:
    cmd= ["oc", verb, resource, "-n", namespace]
  else:
    cmd= ["oc", verb, resource, "-n", namespace, "-o", output]
  rc, output = command(cmd, retries=3, no_log=True)
  if rc != 0:
    logger.error(f"vpa-latency, oc {verb} {resource} rc: {rc}")
  else:
    with open(os.path.join(diagnostic_data_dir, "{}.{}".format(resource, verb)), "w") as f:
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

  # Get and describe the VPA
  oc_gather("get", "vpa", cliargs.namespace, diagnostic_data_dir)
  oc_gather("get", "vpa", cliargs.namespace, diagnostic_data_dir, "yaml")
  oc_gather("describe", "vpa", cliargs.namespace, diagnostic_data_dir)

  # Get and describe the pods
  oc_gather("get", "po", cliargs.namespace, diagnostic_data_dir)
  oc_gather("get", "po", cliargs.namespace, diagnostic_data_dir, "yaml")
  oc_gather("describe", "po", cliargs.namespace, diagnostic_data_dir)

  # Get and describe the deployments
  oc_gather("get", "deploy", cliargs.namespace, diagnostic_data_dir)
  oc_gather("get", "deploy", cliargs.namespace, diagnostic_data_dir, "yaml")
  oc_gather("describe", "deploy", cliargs.namespace, diagnostic_data_dir)

  # Get the logs for the pods
  for pod in po_data["items"]:
    rc, output = command(["oc", "logs", "-n", cliargs.namespace, pod["metadata"]["name"]], retries=3, no_log=True)
    if rc != 0:
      logger.error("vpa-latency, oc logs rc: {}".format(rc))
    with open(os.path.join(diagnostic_data_dir, "{}.log".format(pod["metadata"]["name"])), "w") as f:
      f.write(output)
    rc, output = command(["oc", "logs", "-n", cliargs.namespace, pod["metadata"]["name"], "-p"], retries=3, no_log=True)
    if rc != 0:
      logger.error("vpa-latency, oc logs rc: {}".format(rc))
    with open(os.path.join(diagnostic_data_dir, "{}.previous.log".format(pod["metadata"]["name"])), "w") as f:
      f.write(output)
