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

import logging
import os
import subprocess
import time

logger = logging.getLogger("vpa-latency")


def command(cmd, cmd_directory="", retries=1, retry_backoff=True, no_log=False, readlines=False):
  if cmd_directory != "":
    logger.debug("Command Directory: {}".format(cmd_directory))
    working_directory = os.getcwd()
    os.chdir(cmd_directory)

  tries = 1
  while tries <= retries:
    if tries > 1 and retry_backoff:
      time.sleep(1 * (tries - 1))
    logger.info("Command({}): {}".format(tries, " ".join(cmd)))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, universal_newlines=True)
    if readlines:
      output = ""
      while True:
        output_line = process.stdout.readline()
        if output_line.strip() != "":
          if not no_log:
            logger.info("Output : {}".format(output_line.strip()))
          if output == "":
            output = output_line.strip()
          else:
            output = "{}\n{}".format(output, output_line.strip())
        return_code = process.poll()
        if return_code is not None:
          for output_line in process.stdout.readlines():
            if output_line.strip() != "":
              if not no_log:
                logger.info("Output : {}".format(output_line.strip()))
              if output == "":
                output = output_line
              else:
                output = "{}\n{}".format(output, output_line.strip())
          logger.debug("Return Code: {}".format(return_code))
          break
    else:
      output = process.communicate()[0]
      return_code = process.returncode
    tries += 1
    # Break from retry loop if successful
    if retries > 1 and return_code == 0:
      break
  if cmd_directory != "":
    os.chdir(working_directory)
  return return_code, output
