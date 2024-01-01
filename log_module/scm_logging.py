# scm_logging.py

import logging
import os
import time

# Configure logging
def setup_logging():
    logging.basicConfig(filename='debug-log.txt', level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

# Function to mark the start of the run in the log
def mark_start_of_run_in_log(log_file):
    if os.path.exists(log_file):
        position = os.path.getsize(log_file)
    else:
        position = 0

    with open(log_file, 'a') as file:
        start_marker = f"\n===== Script Run Start: {time.ctime()} =====\n"
        file.write(start_marker)
    return position

# Function to print warnings and errors from log
def print_warnings_and_errors_from_log(log_file, start_position):
    try:
        with open(log_file, 'r') as file:
            file.seek(start_position)  # Jump to the start of the current run
            for line in file:
                if "WARNING" in line or "ERROR" in line or "CRITICAL" in line:
                    print(line.strip())
    except FileNotFoundError:
        print("Log file not found.")
