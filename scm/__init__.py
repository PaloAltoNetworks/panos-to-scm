# /project/scm/__init__.py
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
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from .process import RuleProcessor

class PanApiHandler:
    BASE_URL = "https://api.sase.paloaltonetworks.com"

    def __init__(self, session):
        self.session = session

    def ensure_valid_token(self):
        """ Ensure the session token is valid. """
        self.session.ensure_valid_token()

    def list_object(self, endpoint, folder_scope, limit, position):
        """Retrieve a list of objects."""

        self.ensure_valid_token()

        if position:
            url = f"{self.BASE_URL}{endpoint}position={position}&folder={folder_scope}&limit={limit}&offset=0"
        else:
            url = f"{self.BASE_URL}{endpoint}folder={folder_scope}&limit={limit}&offset=0"
        print(url)

        try:
            response = self.session.get(url=url)
        except Exception as err:
            logging.error(f"Error in list_objects: {err}")
            return []  # Return empty list in case of exception

        if response.status_code == 200:
            return response.json().get("data", [])
        else:
            logging.error(f"Error retrieving list: Status Code {response.status_code}, Response: {response.text}")
            return []  # Return empty list in case of non-200 response

    def move_security_rule(self, rule_id, folder, destination, destination_rule=None, rulebase="pre"):
        """Move a security rule to a specified position."""
        endpoint = f"/sse/config/v1/security-rules/{rule_id}:move"
        url = f"{self.BASE_URL}/{endpoint}"
        payload = {
            "destination": destination,
            "rulebase": rulebase
        }
        if destination_rule is not None:
            payload["destination_rule"] = destination_rule

        self.ensure_valid_token()  # Ensure token is valid before making the request

        response = self.session.post(url, json=payload)
        if response.status_code != 200:
            logging.error(f"Error moving rule {rule_id}: {response.text}")
            return False  # Indicates failure
        else:
            logging.info(f"Successfully moved rule {rule_id}")
            return True  # Indicates success

    def get_object(self, endpoint, retries=1, delay=0.5):
        """ Retrieve a specific object from the API. """
        url = f"{self.BASE_URL}{endpoint}"
        for attempt in range(retries + 1):
            try:
                self.ensure_valid_token()
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    return response.json()['data']
                else:
                    logging.error(f"API Error when retrieving object: {response.json()}, Status Code: {response.status_code}")
                    if attempt < retries:
                        time.sleep(delay)
            except Exception as e:
                logging.error(f"Exception occurred when retrieving object: {str(e)}")
                if attempt < retries:
                    time.sleep(delay)

        return []

    def create_object(self, endpoint, item_data, retries=1, delay=0.5):
        """ Create an object via the API. """
        url = f"{self.BASE_URL}{endpoint}"
        # print(url)
        for attempt in range(retries + 1):
            try:
                self.ensure_valid_token()
                response = self.session.post(url, json=item_data, timeout=10)
                # print(item_data)
                if response.status_code == 201:
                    return 'This object created', item_data['name']
                else:
                    error_response = response.json()
                    if response.status_code == 400:
                        if "object already exists" in str(error_response).lower():
                            logging.info(f"Object already exists for '{item_data.get('name', '')}'")
                            return 'This object exists', item_data['name']
                        if "is not a valid reference" in str(error_response).lower():
                            logging.warning(f"Invalid reference in object '{item_data.get('name', '')}'")
                            time.sleep(delay)
                            continue
                        if "max retries exceeded" in str(error_response).lower():
                            logging.warning(f"You might be hitting rate limiter with object '{item_data.get('name', '')}")
                            time.sleep(delay)
                            continue
                        else:
                            logging.error(f"API Error for '{item_data.get('name', '')}': Response: {response.text}, Status Code: {response.status_code}")
                    return 'error creating object', item_data['name'], "Error: Object creation failed"
            except Exception as e:
                logging.error(f"Exception occurred for '{item_data.get('name', '')}': {str(e)}")
                if attempt < retries:
                    time.sleep(delay)
                else:
                    return 'error creating object', item_data['name'], f"Exception: {str(e)}"

        return 'error creating object', item_data['name'], "Failed after retries"

    def create_objects(self, scope, start_index, object_type, data, max_workers, object_name_field='name', extra_query_params=''):
        """ Create multiple objects via the API in parallel. """
        endpoint = f"{object_type}{extra_query_params}&type=container&folder={scope}"
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            print(f'Running with {max_workers} workers.')
            logging.info(f'Running with {max_workers} workers.')
            futures = [executor.submit(self.create_object, endpoint, item_data, retries=2, delay=0.5) for item_data in data[start_index:]]
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                print(result)
                logging.info(result)

        return results

    def update_object(self, endpoint, item_data, retries=1, delay=0.5):
        """ Update an object via the API. """
        # Similar logic to create_object, but using session.put

    def delete_object(self, endpoint, retries=1, delay=0.5):
        """ Delete an object via the API. """
        # Similar logic to get_object, but using session.delete

class SCMObjectManager:
    def __init__(self, api_handler, folder_scope, configure, obj_module, obj_types):
        self.api_handler = api_handler
        self.folder_scope = folder_scope
        self.configure = configure
        self.obj = obj_module
        self.obj_types = obj_types 

    def fetch_objects(self, obj_type, limit='10000', position=''):
        endpoint = obj_type._endpoint
        all_objects = self.api_handler.list_object(endpoint, self.folder_scope, limit, position)
        return set(o['name'] for o in all_objects)

    def fetch_rules(self, obj_type, limit='10000', position=''):
        endpoint = obj_type._endpoint

        all_objects = self.api_handler.list_object(endpoint, self.folder_scope, limit, position)
        return [o for o in all_objects if 'name' in o and 'folder' in o]

    def get_current_objects(self, obj_types, max_workers=8, limit='10000', **kwargs):
        print(f"Running with {max_workers} workers.")  # Add this line to print the number of workers

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_obj_type = {
                executor.submit(self.fetch_objects, obj_type, limit, **kwargs.get(obj_type.__name__, {})): obj_type 
                for obj_type in obj_types
            }
            results = {}
            for future in as_completed(future_to_obj_type):
                obj_type = future_to_obj_type[future]
                try:
                    data = future.result()
                    results[obj_type] = data
                except Exception as exc:
                    print(f'{obj_type.__name__} generated an exception: {exc}')
            return results

    def get_new_entries(self, parsed_data, current_objects):
        new_entries = {}
        for obj_type in current_objects.keys():
            entry_type_name = obj_type.__name__
            # Generate the key name in a format that matches the parsed_data keys
            parsed_data_key = self._generate_key_name(entry_type_name)
            if parsed_data_key in parsed_data:
                current_set = current_objects[obj_type]
                new_entries[entry_type_name] = [o for o in parsed_data[parsed_data_key] if o['name'] not in current_set]
            else:
                # Handle the case where the key is not found in parsed_data
                print(f"Warning: Key '{parsed_data_key}' not found in parsed_data.")
        return new_entries

    def _generate_key_name(self, entry_type_name):
        # Modify this method to generate the key name as per your requirement
        return entry_type_name

    def post_new_entries(self, new_entries, folder_scope, device_group_name):
        for obj_type in self.obj_types:  # Iterate over the predefined order of object types
            entry_type_name = obj_type.__name__
            if entry_type_name in new_entries:
                entries = new_entries[entry_type_name]
                if entries:
                    entry_class = getattr(self.obj, entry_type_name)
                    self.configure.post_entries(folder_scope, entries, entry_class, extra_query_params='')
                else:
                    message = f"No new {entry_type_name} entries to create from parsed data"
                    if device_group_name:
                        message += f" (Device Group: {device_group_name})"
                    message += f" for SCM Folder: {folder_scope}."
                    print(message)
                    logging.info(message)
            else:
                print(f"Warning: {entry_type_name} not found in new entries.")

    def process_security_rules(self, parsed_data, xml_file_path, rule_order, limit='10000'):
        # Logic to process security rules
        pre_rules = self.fetch_rules(self.obj.SecurityRule, limit, position='pre')
        post_rules = self.fetch_rules(self.obj.SecurityRule, limit, position='post')
        current_rules_pre = [rule for rule in pre_rules if rule['folder'] == self.folder_scope]
        current_rules_post = [rule for rule in post_rules if rule['folder'] == self.folder_scope]
        current_rule_names_pre = set(rule['name'] for rule in current_rules_pre)
        current_rule_names_post = set(rule['name'] for rule in current_rules_post)
        security_rule_pre_entries = parsed_data['security_pre_rules']
        security_rule_post_entries = parsed_data['security_post_rules']
        rules_to_create_pre = [rule for rule in security_rule_pre_entries if rule['name'] not in current_rule_names_pre]
        rules_to_create_post = [rule for rule in security_rule_post_entries if rule['name'] not in current_rule_names_post]

        rule_types = [
            (rules_to_create_pre, "?position=pre", "pre-rules"),
            (rules_to_create_post, "?position=post", "post-rules")
        ]

        for rules, extra_query_param, rule_type_name in rule_types:
            if rules:
                self.configure.set_max_workers(4)
                self.configure.post_entries(self.folder_scope, rules, self.obj.SecurityRule, extra_query_params=extra_query_param)
            else:
                message = f"No new {rule_type_name} to create from XML: {xml_file_path}"
                print(message)
                logging.info(message)

        # Reorder rules if necessary
        self.reorder_rules_if_needed(security_rule_pre_entries, current_rules_pre, rule_order, position='pre')
        self.reorder_rules_if_needed(security_rule_post_entries, current_rules_post, rule_order, position='post')

    def reorder_rules_if_needed(self, security_rule_entries, current_rules, rule_order, position):
        # Use self.obj.SecurityRule to initialize rule_order if not passed
        rule_order = rule_order or self.obj.SecurityRule(self.api_handler)
        if not RuleProcessor.is_rule_order_correct(current_rules, security_rule_entries):
            self.configure.set_max_workers(4)
            self.configure.check_and_reorder_rules(rule_order, self.folder_scope, security_rule_entries, limit='10000', position=position)
