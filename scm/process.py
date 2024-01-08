# /project/scm/process.py

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

from scm import PanApiHandler
from concurrent.futures import ThreadPoolExecutor
import logging
import time
import xml.etree.ElementTree as ET

class Processor:
    def __init__(self, api_handler, max_workers):
        self.api_handler = api_handler
        self.max_workers = max_workers

    def post_entries(self, folder_scope, entries, entry_type, obj_class, extra_query_params):
        if not entries:
            print("No entries to process.")
            return
        # Start the timer for object creation
        start_time_objects = time.time()

        initial_entry_count = len(entries)
        print(f"Processing {len(entries)} {entry_type} entries in parallel.")
        logging.info(f"Processing {len(entries)} {entry_type} entries in parallel.")
        created_count, exists_count, error_count = 0, 0, 0
        error_objects = []

        endpoint = obj_class.get_endpoint() + extra_query_params
        results = self.api_handler.create_objects(folder_scope, 0, endpoint, entries, self.max_workers)
        for result in results:
            if len(result) == 3:
                status, name, error_message = result
                if status == 'error creating object':
                    error_count += 1
                    error_objects.append(name)  # Reduced verbosity - make it (name, error_message) if you want more
            elif len(result) == 2:
                status, name = result
                if status == 'This object created':
                    created_count += 1
                elif status == 'This object exists':
                    exists_count += 1

        print(f"The processing of {entry_type} is complete.")
        logging.info((f"The processing of {entry_type} is complete."))
        print(f"Summary: {created_count} created, {exists_count} already existed, {error_count} errors.")
        potential_missing_objects = initial_entry_count - (created_count + exists_count)
        print(f"Initial Object/Policy count: {initial_entry_count}. Potential missing objects: {potential_missing_objects}")
        logging.info(f"Initial Object/Policy count: {initial_entry_count}. Potential missing objects: {potential_missing_objects}")
        print()
        if error_objects:
            print("Objects with errors:")
            for error in error_objects:
                print(f" - {error}")
                logging.error(f" - {error}")
        # Return the count of processed entries
        # Print the time taken for object creation
        end_time_objects = time.time()
        print(f"Time taken for creating {entry_type}: {end_time_objects - start_time_objects:.2f} seconds\n")
        return created_count, exists_count, error_count

    def reorder_rules(self, security_rule_obj, folder_scope, original_rules, current_rules):
        current_rule_ids = {rule['name']: rule['id'] for rule in current_rules}
        current_order = [rule['name'] for rule in current_rules]
        desired_order = [rule['name'] for rule in original_rules if rule['name'] in current_rule_ids]

        max_attempts = 8
        attempts = 0

        while current_order != desired_order and attempts < max_attempts:
            attempts += 1
            moves = []

            for i, rule_name in enumerate(desired_order[:-1]):
                if current_order.index(rule_name) > current_order.index(desired_order[i + 1]):
                    rule_id = current_rule_ids[rule_name]
                    target_rule_id = current_rule_ids[desired_order[i + 1]]
                    moves.append((rule_id, target_rule_id))
                    print(f"Prepared move: Rule '{rule_name}' (ID: {rule_id}) before '{desired_order[i + 1]}' (ID: {target_rule_id})")

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                print(f'Currently utilizing {int(self.max_workers)} workers.')
                futures = [executor.submit(security_rule_obj.move_rule, rule_id, folder_scope, "before", target_rule_id) for rule_id, target_rule_id in moves]
                for future in futures:
                    future.result()  # Wait for each move to complete

            if moves:
                # Only fetch current rules if there were moves made
                current_rules = security_rule_obj.list_security_rules(folder_scope, "pre")
                current_order = [rule['name'] for rule in current_rules if rule['name'] != 'default']
                print(f"Updated rule order after attempt {attempts}: {current_order}")
                logging.info(f"Updated rule order after attempt {attempts}: {current_order}")

        if attempts >= max_attempts:
            print("Reached maximum attempts to reorder rules. Exiting loop.")
            logging.warning("Reached maximum attempts to reorder rules. Exiting loop.")
            print("Final current order:", current_order)
            print("Desired order:", desired_order)

    def parse_config_and_set_scope(self, xml_file_path):
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        device_group_xpath = root.find('.//devices/entry/device-group')
        device_group_name = None

        if device_group_xpath is not None:
            # Panorama configuration
            config_choice = input("Is this a Panorama 'shared' configuration or 'device-group' configuration? Enter 'shared' or 'device-group': ").strip().lower()
            if config_choice == 'device-group':
                device_group_name = input("Enter the device-group name: ").strip()
                confirm_folder = input('What folder do you want the objects/policies to end up in? \n Use All for "Global" -Example "US-East-DC1" This is Case Sensitive: ').strip()
                folder_scope = confirm_folder
                config_type = 'panorama/device-group'
            else:
                confirm_global = input("Do you want these objects/policies to end up in the Global Folder on SCM? yes/no: ").strip().lower()
                folder_scope = "All" if confirm_global == 'yes' else input('Enter folder name: ').strip()
                config_type = 'panorama/shared'
        else:
            # Local configuration
            confirm_folder = input('What folder do you want the objects/policies to end up in? \n Use All for "Global" -Example "US-East-DC1" This is Case Sensitive: ').strip()
            folder_scope = confirm_folder
            config_type = 'local'

        return folder_scope, config_type, device_group_name

    def check_and_reorder_rules(self, security_rule_obj, folder_scope, original_rules):
        rules_in_correct_order = False
        last_known_order = None
        start_time_reordering = time.time()

        while not rules_in_correct_order:
            current_rules_pre_updated = security_rule_obj.list_security_rules(folder_scope, "pre")
            current_order = [rule['name'] for rule in current_rules_pre_updated if rule['name'] != 'default']

            if current_order == last_known_order:
                print("No change in rule order detected. Exiting reordering process.")
                break
            last_known_order = current_order

            desired_order = [rule['name'] for rule in original_rules if rule['name'] != 'default']

            if current_order != desired_order:
                print("Reordering rules now..")
                self.reorder_rules(security_rule_obj, folder_scope, original_rules, current_rules_pre_updated)
            else:
                rules_in_correct_order = True
                end_time_objects = time.time()
        end_time_reordering = time.time()
        print(f"Time taken for reordering rules: {end_time_reordering - start_time_reordering:.2f} seconds")
        return last_known_order
