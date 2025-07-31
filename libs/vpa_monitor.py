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

from datetime import datetime
import json
import logging
import time
import os
from libs.command import command
import time
from threading import Thread
import traceback


logger = logging.getLogger("vpa-latency")


# Normalize the memory recommendation from VPA
def normalize_memory(raw_memory):
  stripped = raw_memory.strip()
  # Define multipliers for SI (decimal) and IEC (binary) prefixes
  multipliers = {
      'k': 1000,
      'M': 1000**2,
      'G': 1000**3,
      'T': 1000**4,
      'P': 1000**5,
      'E': 1000**6,
      'Ki': 1024,
      'Mi': 1024**2,
      'Gi': 1024**3,
      'Ti': 1024**4,
      'Pi': 1024**5,
      'Ei': 1024**6,
  }

  # Handle case where memory value passed is just "bytes"
  try:
      return int(stripped)
  except ValueError:
      pass  # Pass to determine suffix and convert

  logger.debug("Converting memory value '{}'".format(stripped))
  for suffix in sorted(multipliers.keys(), key=len, reverse=True):
    if stripped.endswith(suffix):
      numeric_part = stripped[:-len(suffix)]
      return int(float(numeric_part) * multipliers[suffix])

  logger.error("Invalid memory format for '{}'".format(stripped))
  return -1


class VPAMonitor(Thread):
  def __init__(self, namespace, vpa_name, monitor_data, polls_csv, transitions_csv, poll_interval):
    super(VPAMonitor, self).__init__()
    self.namespace = namespace
    self.vpa_name = vpa_name
    self.monitor_data = monitor_data
    self.polls_csv = polls_csv
    self.transitions_csv = transitions_csv
    self.poll_interval = poll_interval
    self.signal = True

  def _real_run(self):
    logger.info("Starting VPA Monitor")

    while self.signal:
      start_poll_time = time.time()

      logger.debug("Polling for VPA recommendations")
      oc_cmd = ["oc", "get", "vpa", "-n", self.namespace, self.vpa_name, "-o", "json"]
      rc, output = command(oc_cmd, retries=3, no_log=True)
      if rc != 0:
        logger.error("vpa-latency, oc get vpa rc: {}".format(rc))
        vpa_data = {}
      else:
        try:
          vpa_data = json.loads(output)
        except json.decoder.JSONDecodeError:
          logger.warning("vpa JSONDecodeError: {}".format(output[:2500]))

      logger.debug("vpa_data : {}".format(vpa_data))

      recommendations = {}
      if "status" in vpa_data:
        if "recommendation" in vpa_data["status"] and "containerRecommendations" in vpa_data["status"]["recommendation"]:
          for container in vpa_data["status"]["recommendation"]["containerRecommendations"]:
            if container["containerName"] == "stress":
              logger.debug("Stress Container recommendation found")
              recommendations = container
              break
        else:
          logger.warning("Recommendation or containerRecommendations not available yet :: {}".format(vpa_data["status"]))
      else:
        logger.warning("Missing status fields in VPA data")

      sample = {
        "timestamp": start_poll_time,
        "cpu.lowerBound": 0,
        "cpu.target": 0,
        "cpu.uncappedTarget": 0,
        "cpu.upperBound": 0,
        "memory.lowerBound": 0,
        "memory.target": 0,
        "memory.uncappedTarget": 0,
        "memory.upperBound": 0
      }
      if recommendations:
        sample["cpu.lowerBound"] = recommendations["lowerBound"]["cpu"]
        sample["cpu.target"] = recommendations["target"]["cpu"]
        sample["cpu.uncappedTarget"] = recommendations["uncappedTarget"]["cpu"]
        sample["cpu.upperBound"] = recommendations["upperBound"]["cpu"]
        sample["memory.lowerBound"] = normalize_memory(recommendations["lowerBound"]["memory"])
        sample["memory.target"] = normalize_memory(recommendations["target"]["memory"])
        sample["memory.uncappedTarget"] = normalize_memory(recommendations["uncappedTarget"]["memory"])
        sample["memory.upperBound"] = normalize_memory(recommendations["upperBound"]["memory"])


      self.monitor_data["polls"].append(sample)

      # Write csv data
      with open(self.polls_csv, "a") as csv_file:
        csv_file.write("{},{},{},{},{},{},{},{},{}\n".format(
            datetime.utcfromtimestamp(sample["timestamp"]).strftime('%Y-%m-%dT%H:%M:%SZ'),sample["cpu.lowerBound"],sample["cpu.target"],sample["cpu.uncappedTarget"],sample["cpu.upperBound"],sample["memory.lowerBound"],sample["memory.target"],sample["memory.uncappedTarget"],sample["memory.upperBound"]
        ))

        # TODO Calculate if a transition occured
        # TODO Determine if we have transition due to api request

      end_poll_time = time.time()
      poll_time = round(end_poll_time - start_poll_time, 1)
      logger.info("Monitor polled in {}".format(poll_time))

      time_to_sleep = self.poll_interval - poll_time
      if time_to_sleep > 0:
        time.sleep(time_to_sleep)
      else:
        logger.warning("Time to poll exceeded poll interval")
    logger.info("Monitor Thread terminating")

  def run(self):
    try:
      self._real_run()
    except Exception as e:
      logger.error("Error in Monitoring Thread: {}".format(e))
      logger.error('\n{}'.format(traceback.format_exc()))
      os._exit(1)
