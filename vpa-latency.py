#!/usr/bin/env python3
#
# Tool to apply load and determine frequency of VPA recommendations
#
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


# TODO:
# * Normalize CPU cores


import argparse
from datetime import datetime, timezone
import json
from libs.command import command
from libs.diagnostic import gather_diagnostic_data
from libs.vpa_monitor import VPAMonitor
import logging
import os
import urllib3
import requests
import sys
import time


logging.basicConfig(level=logging.INFO, format="%(asctime)s : %(levelname)s : %(threadName)s : %(message)s")
logger = logging.getLogger("vpa-latency")
logging.Formatter.converter = time.gmtime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_report(cliargs, mon_data, total_time, report_dir):
  logger.info("###############################################################################")

  with open("{}/report.txt".format(report_dir), "w") as report:
    log_write(report, "VPA Latency Test Report Card")
    log_write(report, "###############################################################################")
    # Test Parameters
    log_write(report, "* Measurement Time: {}s".format(cliargs.measurement_time))
    log_write(report, "* VPA Recommendation Polling Interval: {}s".format(cliargs.poll_interval))
    log_write(report, "* Namespace: {}".format(cliargs.namespace))
    log_write(report, "  * VPA Name: {}".format(cliargs.vpa_name))
    log_write(report, "  * Route Name: {}".format(cliargs.route_name))
    log_write(report, "* API Request:")
    if cliargs.no_api_request:
      log_write(report, "  * No API Requests to trigger stress-ng")
    else:
      log_write(report, "  * API Request at: {}s".format(cliargs.initial_api_wait))
      log_write(report, "  * Stress-ng Memory: {}G".format(cliargs.stress_memory))
      log_write(report, "  * Stress-ng Timeout: {}s".format(cliargs.stress_timeout))
    log_write(report, "###############################################################################")
    log_write(report, "Total Test Time: {}".format(total_time))
    log_write(report, "###############################################################################")
    log_write(report, "Memory Recommendation changes computed with API request timestamp")
    for change_item in mon_data["mem_recommendation_changes"]:
      if change_item["api_ts"] == "Yes":
        if change_item["metric"] == "memory.target":
          log_change_item(report, change_item)
    for change_item in mon_data["mem_recommendation_changes"]:
      if change_item["api_ts"] == "Yes":
        if change_item["metric"] == "memory.uncappedTarget":
          log_change_item(report, change_item)
    log_write(report, "###############################################################################")
    log_write(report, "Recommendation changes")
    for change_item in mon_data["mem_recommendation_changes"]:
      if change_item["api_ts"] == "NA":
        if change_item["metric"] == "memory.target":
          log_change_item(report, change_item)
    for change_item in mon_data["mem_recommendation_changes"]:
      if change_item["api_ts"] == "NA":
        if change_item["metric"] == "memory.uncappedTarget":
          log_change_item(report, change_item)


def log_change_item(report, change_item):
  log_write(report, "VPA Recommendation {} {} change - {} GiB".format(change_item["type"], change_item["metric"], change_item["change_gib"]))
  log_write(report, "  Latency")
  if change_item["api_ts"] == "NA":
    log_write(report, "  * Previous recorded TS: {}".format(datetime.fromtimestamp(change_item["old_ts"], tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')))
  else:
    log_write(report, "  * API Request TS: {}".format(datetime.fromtimestamp(change_item["old_ts"], tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')))
  log_write(report, "  * Recommendation TS: {}".format(datetime.fromtimestamp(change_item["timestamp"], tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')))
  log_write(report, "  * Latency: {} seconds".format(change_item["latency"]))
  log_write(report, "  Values")
  log_write(report, "  * Original: {} bytes :: {} GiB".format(change_item["old_value"], change_item["old_value_gib"]))
  log_write(report, "  * New: {} bytes :: {} GiB".format(change_item["new_value"], change_item["new_value_gib"]))
  log_write(report, "  * Change: {} bytes :: {} GiB".format(change_item["change"], change_item["change_gib"]))


def log_write(file, message):
  logger.info(message)
  file.write(message + "\n")


def stress_api_request(api_route, stress_memory, stress_timeout, monitor_data, requests_csv_file):
  request_start_time = time.time()
  endpoint = "https://{}/stress?memory={}G&timeout={}".format(api_route, stress_memory, stress_timeout)
  logger.info("Requesting stress api :: {}".format(endpoint))
  response = requests.get(endpoint, verify=False)
  request = {
    "timestamp": request_start_time,
    "endpoint": endpoint,
    "memory": stress_memory,
    "timeout": stress_timeout,
    "response": response.status_code
  }
  monitor_data["api_requests"].append(request)
  request_time = round(time.time() - request_start_time, 3)
  logger.info("Stress API response code: {}, Request Time: {}".format(response.status_code, request_time))

  with open(requests_csv_file, "a") as csv_file:
    csv_file.write("{},{},{},{},{}\n".format(datetime.fromtimestamp(request["timestamp"], tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),request["endpoint"],request["memory"],request["timeout"],request["response"]))


def main():
  parser = argparse.ArgumentParser(
      description="Tool to apply resource load to a container and record how long for a VerticalPodAutoscaler recommendations",
      prog="vpa-latency.py", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

  # Workload pattern/phase arguments
  parser.add_argument("-m", "--measurement-time", type=int, default=180,
                      help="Total amount of time (seconds) the script will poll VPA for recommendations")
  parser.add_argument("-i", "--initial-api-wait", type=int, default=60,
                      help="Amount of time (seconds) to wait before making the API request for /stress")

  # Arguments to help determine when a new recommendation was made
  parser.add_argument("-p", "--poll-interval", type=float, default=5,
                      help="Time between polling VPA and checkpoint for new recommendations")

  # Arguments for the API request to the gohttp stress endpoint
  parser.add_argument("--no-api-request", action="store_true", default=False,
                      help="Does not send any API request to trigger stress-ng")
  parser.add_argument("-s", "--stress-memory", type=int, default=5,
                      help="Memory (GiB) setting for stress-ng to be passed with API request")
  parser.add_argument("-t", "--stress-timeout", type=int, default=60,
                      help="Timeout (seconds) setting for stress-ng to be passed with API request")

  parser.add_argument("-n", "--namespace", type=str, default="vpa-gohttp-stress-1",
                      help="Namespace of workload and VPA")
  parser.add_argument("-v", "--vpa-name", type=str, default="vpa-stress", help="Name of VPA")
  parser.add_argument("-r", "--route-name", type=str, default="gohttp", help="Name of route for /stress API")

  parser.add_argument("-d", "--debug", action="store_true", default=False, help="Set log level debug")

  cliargs = parser.parse_args()
  if cliargs.debug:
    logger.setLevel(logging.DEBUG)

  # Validate the arguments
  if cliargs.measurement_time < 30:
    logger.error("Measurement time must be > 30, set to {}".format(cliargs.measurement_time))
    sys.exit(1)
  if cliargs.initial_api_wait < 0:
    logger.error("Initial API wait must be >= 0, set to {}".format(cliargs.initial_api_wait))
    sys.exit(1)
  if cliargs.initial_api_wait >= cliargs.measurement_time:
    logger.error("Initial API wait({}) must be < measurement time({})".format(cliargs.initial_api_wait, cliargs.measurement_time))
    sys.exit(1)
  if cliargs.poll_interval < 1:
    logger.error("Poll time must be >= 1, set to {}".format(cliargs.poll_interval))
    sys.exit(1)

  # Display test arguments
  logger.info("VPA Latency Test")
  logger.info("###############################################################################")
  logger.debug("CLI Args: {}".format(cliargs))
  logger.info("* Measurement Time: {}s".format(cliargs.measurement_time))
  logger.info("* VPA Recommendation Polling Interval: {}s".format(cliargs.poll_interval))
  logger.info("* Namespace: {}".format(cliargs.namespace))
  logger.info("  * VPA Name: {}".format(cliargs.vpa_name))
  logger.info("  * Route Name: {}".format(cliargs.route_name))
  logger.info("* API Request:")
  if cliargs.no_api_request:
    logger.info("  * No API Requests to trigger stress-ng")
  else:
    logger.info("  * API Request at: {}s".format(cliargs.initial_api_wait))
    logger.info("  * Stress-ng Memory: {}G".format(cliargs.stress_memory))
    logger.info("  * Stress-ng Timeout: {}s".format(cliargs.stress_timeout))
  if cliargs.debug:
    logger.info("* Debug logging is enabled")
  else:
    logger.info("* Debug logging is disabled")

  # Handle the API Request Route
  logger.info("###############################################################################")
  api_route = ""
  if cliargs.no_api_request:
    logger.info("API request disabled, no route detection required")
  else:
    logger.info("API request enabled, determining route for API requests")
    oc_cmd = ["oc", "get", "route", "-n", cliargs.namespace, cliargs.route_name, "-o", "json"]
    rc, output = command(oc_cmd, retries=3, no_log=True)
    if rc != 0:
      logger.error("vpa-latency, oc get route rc: {}".format(rc))
      sys.exit(1)
    else:
      try:
        route_data = json.loads(output)
      except json.decoder.JSONDecodeError:
        logger.error("route JSONDecodeError: {}".format(output[:2500]))
        sys.exit(1)
    if "spec" in route_data and "host" in route_data["spec"]:
      api_route = route_data["spec"]["host"]
      logger.info("Route is {}".format(api_route))

  # Sort out where to place result artifacts
  base_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
  base_dir_results = os.path.join(base_dir, "results")
  report_dir_name = "{}-vpa-latency".format(datetime.fromtimestamp(time.time(), tz=timezone.utc).strftime("%Y%m%d-%H%M%S"))
  report_dir = os.path.join(base_dir_results, report_dir_name)
  os.mkdir(report_dir)

  requests_csv_file = "{}/requests.csv".format(report_dir)
  polls_csv_file = "{}/polls.csv".format(report_dir)
  cpu_recommendations_csv_file = "{}/cpu_recommendation_changes.csv".format(report_dir)
  memory_recommendations_csv_file = "{}/memory_recommendation_changes.csv".format(report_dir)

  if not cliargs.no_api_request:
    with open(requests_csv_file, "w") as csv_file:
      csv_file.write("timestamp,endpoint,stress_memory,stress_timeout,response\n")

  with open(polls_csv_file, "w") as csv_file:
    csv_file.write("timestamp,cpu.lowerBound,cpu.target,cpu.uncappedTarget,cpu.upperBound,memory.lowerBound,memory.target,memory.uncappedTarget,memory.upperBound\n")

  # with open(cpu_recommendations_csv_file, "w") as csv_file:
  #   csv_file.write("timestamp,old_ts,api_ts,metric,type,latency,new_value,old_value,change\n")

  with open(memory_recommendations_csv_file, "w") as csv_file:
    csv_file.write("timestamp,old_ts,api_ts,metric,type,latency,new_value,old_value,change,new_value_gib,old_value_gib,change_gib\n")

  monitor_data = {
    "api_requests": [],
    "polls": [],
    "cpu_recommendation_changes": [],
    "mem_recommendation_changes": []
  }

  logger.info("###############################################################################")
  logger.info("Results data placed in: {}".format(report_dir))
  if not cliargs.no_api_request:
    logger.info("Storing request data in {}".format(requests_csv_file))
  logger.info("Storing raw polling data in {}".format(polls_csv_file))
  # logger.info("Storing cpu recommendation changes data in {}".format(cpu_recommendations_csv_file))
  logger.info("Storing memory recommendation changes data in {}".format(memory_recommendations_csv_file))
  logger.info("###############################################################################")

  logger.info("Gathering pre-test diagnostic data")
  gather_diagnostic_data(cliargs, report_dir, "pre-test")
  logger.info("Completed gathering pre-test diagnostic data")

  # Start the measurement phase and test
  logger.info("###############################################################################")
  logger.info("Starting measurement phase")

  monitor_thread = VPAMonitor(
      cliargs.namespace, cliargs.vpa_name, monitor_data, polls_csv_file, cpu_recommendations_csv_file,
      memory_recommendations_csv_file, cliargs.poll_interval)
  monitor_thread.start()

  start_time = time.time()
  initial_api_request_completed = False
  if cliargs.no_api_request:
    initial_api_request_completed = True
  expected_api_request_time = start_time + cliargs.initial_api_wait
  expected_end_time = start_time + cliargs.measurement_time
  logger.debug("Measurement Loop Start :: start_time :: {}".format(start_time))
  logger.debug("Measurement Loop Start :: expected_api_request_time :: {}".format(expected_api_request_time))
  logger.debug("Measurement Loop Start :: expected_end_time :: {}".format(expected_end_time))
  wait_logger = 0
  while True:
    current_time = time.time()
    if not initial_api_request_completed and (current_time >= expected_api_request_time):
      logger.info("Completed initial api request phase")
      stress_api_request(api_route, cliargs.stress_memory, cliargs.stress_timeout, monitor_data, requests_csv_file)
      initial_api_request_completed = True
    if current_time >= expected_end_time:
      logger.info("Completed measurement phase")
      break
    time.sleep(.1)
    wait_logger += 1
    # Approximately display this every 30s
    if wait_logger >= 300:
      logger.info("Remaining measurement time: {}s".format(round(expected_end_time - current_time)))
      if not initial_api_request_completed:
        logger.info("Remaining time until api stress request: {}".format(round(expected_api_request_time - current_time)))
      # Dump useful monitor_data
      wait_logger = 0

  # Test loop completed, signal thread to terminate
  logger.info("Stopping VPA Monitor thread may take up to: {}s".format(cliargs.poll_interval))
  monitor_thread.signal = False
  monitor_thread.join()

  # Display report card here
  end_time = time.time()
  total_time = round(end_time - start_time)
  generate_report(cliargs, monitor_data, total_time, report_dir)

  logger.info("Gathering post-test diagnostic data")
  gather_diagnostic_data(cliargs, report_dir, "post-test")
  logger.info("Completed gathering post-test diagnostic data")


if __name__ == "__main__":
  sys.exit(main())
