"""
ISC License

Copyright (c) 2023 Eric Chickering <eric.chickering@gmail.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
import logging
import os
import time

class SCMLogger:
    def __init__(self, log_file='debug-log.txt'):
        self.log_file = log_file

    def setup_logging(self):
        # Perform cleanup of old logs before setting up new logging configuration
        self.cleanup_old_logs()

        # Setting up the new logging configuration
        logging.basicConfig(filename=self.log_file, level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

    def mark_start_of_run_in_log(self):
        if os.path.exists(self.log_file):
            position = os.path.getsize(self.log_file)
        else:
            position = 0

        with open(self.log_file, 'a') as file:
            start_marker = f"\n===== Script Run Start: {time.ctime()} =====\n"
            file.write(start_marker)
        return position

    def print_warnings_and_errors_from_log(self, start_position):
        try:
            with open(self.log_file, 'r') as file:
                file.seek(start_position)  # Jump to the start of the current run
                for line in file:
                    if "WARNING" in line or "ERROR" in line or "CRITICAL" in line:
                        print(line.strip())
        except FileNotFoundError:
            print("Log file not found.")

    def cleanup_old_logs(self):
        if not os.path.exists(self.log_file):
            return

        with open(self.log_file, 'r') as file:
            lines = file.readlines()

        cutoff = time.time() - 24 * 60 * 60  # 24 hours ago
        with open(self.log_file, 'w') as file:
            for line in lines:
                parts = line.split()
                if len(parts) < 2:
                    continue  # Skip lines that don't have enough parts

                try:
                    timestamp = time.strptime(parts[0] + ' ' + parts[1], '%Y-%m-%d %H:%M:%S,%f')
                except ValueError:
                    continue  # Skip lines where the timestamp can't be parsed

                if time.mktime(timestamp) > cutoff:
                    file.write(line)
