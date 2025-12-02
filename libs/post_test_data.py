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


def gather_post_test_data(cliargs, report_dir):
  logger.info("Gathering post-test data")

  rc, output = command(["oc", "get", "po", "-n", cliargs.namespace, "-o", "json"], retries=3, no_log=True)
  if rc != 0:
    logger.error("vpa-latency, oc get po rc: {}".format(rc))
  else:
    try:
      po_data = json.loads(output)
    except json.decoder.JSONDecodeError:
      logger.error("vpa-latency, po JSONDecodeError: {}".format(output[:2500]))
    
  post_test_data_dir = os.path.join(report_dir, "post-test-data")
  os.mkdir(post_test_data_dir)

  # Get and describe the VPA
  rc, output = command(["oc", "get", "vpa", "-n", cliargs.namespace, cliargs.vpa_name], retries=3, no_log=True)
  if rc != 0:
    logger.error("vpa-latency, oc get vpa rc: {}".format(rc))
  with open(os.path.join(post_test_data_dir, "vpa"), "w") as f:
    f.write(output)

  rc, output = command(["oc", "describe", "vpa", "-n", cliargs.namespace, cliargs.vpa_name], retries=3, no_log=True)
  if rc != 0:
    logger.error("vpa-latency, oc describe vpa rc: {}".format(rc))
  with open(os.path.join(post_test_data_dir, "vpa.describe"), "w") as f:
    f.write(output)

  # Get and describe the pods
  rc, output = command(["oc", "get", "po", "-n", cliargs.namespace], retries=3, no_log=True)
  if rc != 0:
    logger.error("vpa-latency, oc get po rc: {}".format(rc))
  with open(os.path.join(post_test_data_dir, "po"), "w") as f:
    f.write(output)

  rc, output = command(["oc", "describe", "po", "-n", cliargs.namespace], retries=3, no_log=True)
  if rc != 0:
    logger.error("vpa-latency, oc describe po rc: {}".format(rc))
  with open(os.path.join(post_test_data_dir, "po.describe"), "w") as f:
    f.write(output)

  # Get and describe the deployments
  rc, output = command(["oc", "get", "deploy", "-n", cliargs.namespace], retries=3, no_log=True)
  if rc != 0:
    logger.error("vpa-latency, oc get deploy rc: {}".format(rc))
  with open(os.path.join(post_test_data_dir, "deploy"), "w") as f:
    f.write(output)

  rc, output = command(["oc", "describe", "deploy", "-n", cliargs.namespace], retries=3, no_log=True)
  if rc != 0:
    logger.error("vpa-latency, oc describe deploy rc: {}".format(rc))
  with open(os.path.join(post_test_data_dir, "deploy.describe"), "w") as f:
    f.write(output)

  # Get the logs for the pods
  for pod in po_data["items"]:
    rc, output = command(["oc", "logs", "-n", cliargs.namespace, pod["metadata"]["name"]], retries=3, no_log=True)
    if rc != 0:
      logger.error("vpa-latency, oc logs rc: {}".format(rc))
    with open(os.path.join(post_test_data_dir, "{}.log".format(pod["metadata"]["name"])), "w") as f:
      f.write(output)
    rc, output = command(["oc", "logs", "-n", cliargs.namespace, pod["metadata"]["name"], "-p"], retries=3, no_log=True)
    if rc != 0:
      logger.error("vpa-latency, oc logs rc: {}".format(rc))
    with open(os.path.join(post_test_data_dir, "{}.previous.log".format(pod["metadata"]["name"])), "w") as f:
      f.write(output)

  logger.info("Completed gathering post-test data")