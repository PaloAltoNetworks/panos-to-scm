# /project/scm/process.py
from concurrent.futures import ThreadPoolExecutor, as_completed
# import scm2.obj as panobject
import logging
import time

class Processor:
    def __init__(self, api_handler, max_workers, obj_module):
        self.api_handler = api_handler
        self.max_workers = max_workers
        self.obj = obj_module  # Added obj_module attribute

    def set_max_workers(self, new_max_workers):
        self.max_workers = new_max_workers

    def post_entries(self, folder_scope, entries, obj_type, extra_query_params):
        if not entries:
            print("No entries to process.")
            return

        start_time_objects = time.time()

        initial_entry_count = len(entries)
        message = obj_type.get_endpoint().replace('/sse/config/v1/','').replace('?','')
        print(f"Processing {len(entries)} {message} entries in parallel.")
        logging.info(f"Processing {len(entries)} {message} entries in parallel.")
        created_count, exists_count, error_count = 0, 0, 0
        error_objects = []

        endpoint = obj_type.get_endpoint() + extra_query_params
        results = self.create_objects(folder_scope, 0, endpoint, entries, self.max_workers)
        for result in results:
            if 'status' in result and 'message' in result and 'name' in result:
                status, message, name = result['status'], result['message'], result['name']
                if status == 'success':
                    # Update this condition based on how you differentiate between created and existing objects
                    if message == 'Object processed':
                        created_count += 1
                    else:
                        exists_count += 1
                elif status == 'error creating object':
                    error_count += 1
                    error_objects.append(name)  # Add error message if needed

        print(f"The processing of {message} is complete.")
        logging.info(f"The processing of {message} is complete.")
        print(f"Summary: {created_count} created, {exists_count} already existed, {error_count} errors.")
        potential_missing_objects = initial_entry_count - (created_count + exists_count)
        print(f"Initial Object/Policy count: {initial_entry_count}. Potential missing objects: {potential_missing_objects}")
        logging.info(f"Initial Object/Policy count: {initial_entry_count}. Potential missing objects: {potential_missing_objects}")

        if error_objects:
            print("Objects with errors:")
            for error in error_objects:
                print(f" - {error}")
                logging.error(f" - {error}")

        end_time_objects = time.time()
        print(f"Time taken for creating {message}: {end_time_objects - start_time_objects:.2f} seconds\n")
        return created_count, exists_count, error_count

    def create_objects(self, scope, start_index, endpoint, data, max_workers, object_name_field='name', extra_query_params=''):
        """ Create multiple objects via the API in parallel. """
        endpoint = f"{endpoint}{extra_query_params}&folder={scope}"
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            print(f'Running with {max_workers} workers.')
            logging.info(f'Running with {max_workers} workers.')
            futures = [executor.submit(self.api_handler.post, endpoint, item_data, retries=2, delay=0.5) for item_data in data[start_index:]]
            for future in as_completed(futures):
                response = future.result()
                if response['status'] in ['success', 'exists']:
                    results.append(response)
                else:
                    logging.error(f"Error creating object: {response}")
                    results.append(response)  # You might still want to include this in results for tracking
                print(response)
                logging.info(response)

        return results

    def reorder_rules(self, obj_type, endpoint, folder_scope, original_rules, current_rules, limit, position):
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
                    destination_rule_id = current_rule_ids[desired_order[i + 1]]
                    move_data = {
                        "destination": "before",
                        "rulebase": position,
                        "destination_rule": destination_rule_id
                    }
                    moves.append((f"{endpoint}/{rule_id}:move", move_data))
                    print(f"Prepared move: Rule '{rule_name}' (ID: {rule_id}) before '{desired_order[i + 1]}' (ID: {destination_rule_id})")

            if not moves:
                break  # Exit loop if no moves are required

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                print(f'Currently utilizing {self.max_workers} workers.')
                futures = [executor.submit(self.api_handler.post, endpoint, move_data) for endpoint, move_data in moves]
                for future in futures:
                    response = future.result()
                    if response['status'] != 'success':
                        logging.error(f"Error moving rule: {response}")
                        # Handle the error appropriately


            # Refetch the rules to update the current order
            all_current_rules = self.api_handler.get(obj_type.get_endpoint(), folder=folder_scope, limit=limit, position=position)
            current_rules = [rule for rule in all_current_rules if rule['folder'] == folder_scope]
            current_order = [rule['name'] for rule in current_rules if rule['name'] != 'default']

    def check_and_reorder_rules(self, obj_type, folder_scope, original_rules, limit, position):
        rules_in_correct_order = False
        start_time_reordering = time.time()

        while not rules_in_correct_order:
            # Fetch current rules from SCM
            # endpoint = self.obj.SecurityRule.get_endpoint()
            endpoint = obj_type.get_endpoint()
            all_current_rules = self.api_handler.get(obj_type.get_endpoint(), folder=folder_scope, limit=limit, position=position)
            endpoint = endpoint.replace('?','')
            current_rules = [rule for rule in all_current_rules if rule['folder'] == folder_scope]
            current_order = [rule['name'] for rule in current_rules if rule['name'] != 'default']

            # Determine the desired order of rules
            desired_order = [rule['name'] for rule in original_rules if rule['name'] != 'default']

            # Check if reordering is needed
            if current_order != desired_order:
                print("Reordering rules now..")
                moves_made = self.reorder_rules(obj_type, endpoint, folder_scope, original_rules, current_rules, limit, position)
                rules_in_correct_order = not moves_made
            else:
                rules_in_correct_order = True

        end_time_reordering = time.time()
        print(f"Time taken for reordering rules: {end_time_reordering - start_time_reordering:.2f} seconds")

class RuleProcessor:
    @staticmethod
    def is_rule_order_correct(current_rules, desired_rules):
        # Check if the order of rules in current_rules matches the order in desired_rules
        current_rule_names = [rule['name'] for rule in current_rules]
        desired_rule_names = [rule['name'] for rule in desired_rules]
        return current_rule_names == desired_rule_names

class SCMObjectManager:
    def __init__(self, api_handler, folder_scope, configure, obj_module, obj_types, sec_obj):
        self.api_handler = api_handler
        self.folder_scope = folder_scope
        self.configure = configure
        self.obj = obj_module
        self.obj_types = obj_types
        self.sec_obj = sec_obj

    def fetch_objects(self, obj_type, limit='10000', position=''):
        endpoint = obj_type._endpoint
        all_objects = self.api_handler.get(endpoint, limit=limit, position=position, folder=self.folder_scope)
        # print(f'All Objects Fetched: {all_objects}')
        return all_objects

    def fetch_rules(self, obj_type, limit='10000', position=''):
        endpoint = obj_type._endpoint
        all_objects = self.api_handler.get(endpoint, limit=limit, position=position, folder=self.folder_scope)
        return [o for o in all_objects if 'name' in o and 'folder' in o]

    def process_objects(self, parsed_data, folder_scope, device_group_name, max_workers=6, limit='10000'):
        print(f'Workers grabbing objects: {max_workers}')
        current_objects = self.get_current_objects(self.obj_types, max_workers=max_workers, limit=limit)
        new_entries, updated_entries = self.get_new_and_updated_entries(parsed_data, current_objects)

        # Only call post_new_entries if there are new entries to post
        if any(new_entries.values()):
            self.post_new_entries(new_entries, folder_scope, device_group_name)

        self.update_existing_entries(updated_entries, folder_scope, device_group_name)


    def get_current_objects(self, obj_types, max_workers=6, limit='10000', **kwargs):
        logging.info(f"Running with {max_workers} workers.")
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_obj_type = {
                executor.submit(self.fetch_objects, obj_type, limit, **kwargs.get(obj_type.__name__, {})): obj_type 
                for obj_type in obj_types
            }
            for future in as_completed(future_to_obj_type):
                obj_type = future_to_obj_type[future]
                try:
                    data = future.result()
                    logging.debug(f"Data fetched for {obj_type.__name__}: {data}")
                    results[obj_type] = data  # Store the entire fetched object data
                except Exception as exc:
                    logging.error(f'Exception fetching data for {obj_type.__name__}: {exc}')
            return results

    def get_new_and_updated_entries(self, parsed_data, current_objects):
        new_entries = {}
        updated_entries = {}
        for obj_type in current_objects.keys():
            entry_type_name = obj_type.__name__
            parsed_data_key = self._generate_key_name(entry_type_name)
            if parsed_data_key in parsed_data:
                current_set = current_objects[obj_type]
                current_names = set(o['name'] for o in current_set if isinstance(o, dict))
                # print(f"Current set for {entry_type_name}: {current_set}")
                # print(f"Parsed data for {entry_type_name}: {parsed_data[parsed_data_key]}")
                for parsed_obj in parsed_data[parsed_data_key]:
                    name = parsed_obj['name']
                    if name not in current_names:
                        # print(f"New object found for {name} in {entry_type_name}")
                        new_entries.setdefault(entry_type_name, []).append(parsed_obj)
                    else:
                        existing_obj = next(o for o in current_set if o['name'] == name)
                        parsed_obj_with_id = {**parsed_obj, 'id': existing_obj.get('id')}
                        if self.needs_update(parsed_obj_with_id, existing_obj):
                            print(f"Update needed for {entry_type_name}: {name}")
                            updated_entries.setdefault(entry_type_name, []).append(parsed_obj_with_id)
            else:
                print(f"Warning: Key '{parsed_data_key}' not found in parsed_data.")
        return new_entries, updated_entries

    @staticmethod
    def needs_update(new_object, current_object):
        if not current_object:
            print(f"Object '{new_object['name']}' not found in current set.")
            return False

        def deep_compare(value1, value2):
            # If one is an empty list/dict and the other is None (or not present), treat them as equal
            if (value1 == [] and value2 is None) or (value1 is None and value2 == []):
                return False
            if value1 is None and value2 is None:
                return False  # Both are None, no change
            if value1 is None or value2 is None:
                return True   # One is None, the other isn't, change detected
            if isinstance(value1, dict) and isinstance(value2, dict):
                for key in value1:
                    if key not in value2:
                        print(f"Key '{key}' found in new object but not in existing object.")
                        return True
                    if deep_compare(value1[key], value2[key]):
                        print(f"Difference detected in dict at key '{key}'")
                        return True
                return False
            elif isinstance(value1, list) and isinstance(value2, list):
                if len(value1) != len(value2):
                    print(f"Difference detected in list length. New: {len(value1)}, Existing: {len(value2)}")
                    return True
                for item1, item2 in zip(value1, value2):
                    if isinstance(item1, dict) and isinstance(item2, dict):
                        if deep_compare(item1, item2):
                            return True
                    elif item1 != item2:
                        print(f"Difference detected in list item. New: {item1}, Existing: {item2}")
                        return True
                return False
            else:
                if value1 != value2:
                    print(f"Difference detected in value. New: {value1}, Existing: {value2}")
                    return True
                return False

        for key, value in new_object.items():
            if key == 'name':
                continue
            existing_value = current_object.get(key)
            try:
                if deep_compare(value, existing_value):
                    print(f"Change detected for '{key}' in object '{new_object['name']}'.")
                    return True
            except Exception as e:
                print(f"Error comparing '{key}' in '{new_object['name']}': {e}")

        # print(f"No changes detected for object '{new_object['name']}'.")
        return False

    def update_existing_entries(self, updated_entries, folder_scope, device_group_name):
        for obj_type in self.obj_types:
            entry_type_name = obj_type.__name__
            if entry_type_name in updated_entries:
                entries = updated_entries[entry_type_name]
                if entries:
                    entry_class = getattr(self.obj, entry_type_name)
                    for entry in entries:
                        object_id = entry.get('id')
                        if not object_id:
                            print(f"Warning: Object ID not found for {entry['name']} in {entry_type_name}. Skipping update.")
                            continue
                        endpoint = entry_class.get_endpoint().replace('?','') + '/' + object_id
                        print(f"Updating {entry_type_name}: {entry['name']} at endpoint: {endpoint}")
                        result = self.api_handler.put(endpoint, entry)
                        if result['status'] == 'success':
                            print(f"Updated {entry_type_name}: {entry['name']}")
                        else:
                            print(f"Failed to update {entry_type_name}: {entry['name']}, Reason: {result['message']}")
                else:
                    print(f"No entries to update for {entry_type_name}.")
            # else:
            #     print(f"No updated entries found for {entry_type_name}.")

    def _generate_key_name(self, entry_type_name):
        return entry_type_name.replace(' ', '-')

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

    def process_security_rules(self, api_handler, sec_obj, parsed_data, xml_file_path, limit='10000'):
        # Logic to process security rules
        pre_rules = self.fetch_rules(sec_obj, limit, position='pre')
        post_rules = self.fetch_rules(sec_obj, limit, position='post')
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
                self.configure.post_entries(self.folder_scope, rules, sec_obj, extra_query_params=extra_query_param)
            else:
                message = f"No new {rule_type_name} to create from XML: {xml_file_path}"
                print(message)
                logging.info(message)

        # Reorder rules if necessary
        self.reorder_rules_if_needed(sec_obj, security_rule_pre_entries, current_rules_pre, api_handler, position='pre')
        self.reorder_rules_if_needed(sec_obj, security_rule_post_entries, current_rules_post, api_handler, position='post')


    def reorder_rules_if_needed(self, sec_obj, security_rule_entries, current_rules, api_handler, position):
        # Use self.obj.SecurityRule to initialize api_handler if not passed
        api_handler = api_handler
        if not RuleProcessor.is_rule_order_correct(current_rules, security_rule_entries):
            self.configure.set_max_workers(4)
            self.configure.check_and_reorder_rules(sec_obj, self.folder_scope, security_rule_entries, limit='10000', position=position)
