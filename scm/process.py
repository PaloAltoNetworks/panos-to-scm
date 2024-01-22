# /project/scm/process.py
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time

class Processor:
    def __init__(self, api_handler, max_workers, obj_module):
        self.api_handler = api_handler
        self.max_workers = max_workers
        self.obj = obj_module  # Added obj_module attribute

    def set_max_workers(self, new_max_workers):
        self.max_workers = new_max_workers

    def post_entries(self, folder_scope, entries, obj_class, extra_query_params):
        if not entries:
            print("No entries to process.")
            return
        # Start the timer for object creation
        start_time_objects = time.time()

        initial_entry_count = len(entries)
        message = obj_class.get_endpoint().replace('/sse/config/v1/','').replace('?','')
        print(f"Processing {len(entries)} {message} entries in parallel.")
        logging.info(f"Processing {len(entries)} {message} entries in parallel.")
        created_count, exists_count, error_count = 0, 0, 0
        error_objects = []

        endpoint = obj_class.get_endpoint() + extra_query_params
        results = self.create_objects(folder_scope, 0, endpoint, entries, self.max_workers)
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

        print(f"The processing of {message} is complete.")
        logging.info((f"The processing of {message} is complete."))
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
                result = future.result()
                results.append(result)
                print(result)
                logging.info(result)

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
                    moves.append((rule_id, destination_rule_id))
                    print(f"Prepared move: Rule '{rule_name}' (ID: {rule_id}) before '{desired_order[i + 1]}' (ID: {destination_rule_id})")

            if not moves:
                break  # Exit loop if no moves are required

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                print(f'Currently utilizing {self.max_workers} workers.')
                futures = [executor.submit(self.api_handler.move, f"{endpoint}/{rule_id}:move", rule_id, destination_rule_id, position, destination= "before") for rule_id, destination_rule_id in moves]
                for future in futures:
                    future.result()

            # Refetch the rules to update the current order
            all_current_rules = self.api_handler.list(obj_type.get_endpoint(), folder_scope, limit, position)
            current_rules = [rule for rule in all_current_rules if rule['folder'] == folder_scope]
            current_order = [rule['name'] for rule in current_rules if rule['name'] != 'default']

    def check_and_reorder_rules(self, sec_obj, folder_scope, original_rules, limit, position):
        rules_in_correct_order = False
        start_time_reordering = time.time()

        while not rules_in_correct_order:
            # Fetch current rules from SCM
            # endpoint = self.obj.SecurityRule.get_endpoint()
            endpoint = sec_obj.get_endpoint()
            all_current_rules = self.api_handler.list(endpoint, folder_scope, limit, position)
            endpoint = endpoint.replace('?','')
            current_rules = [rule for rule in all_current_rules if rule['folder'] == folder_scope]
            current_order = [rule['name'] for rule in current_rules if rule['name'] != 'default']

            # Determine the desired order of rules
            desired_order = [rule['name'] for rule in original_rules if rule['name'] != 'default']

            # Check if reordering is needed
            if current_order != desired_order:
                print("Reordering rules now..")
                moves_made = self.reorder_rules(sec_obj, endpoint, folder_scope, original_rules, current_rules, limit, position)
                rules_in_correct_order = not moves_made
            else:
                rules_in_correct_order = True

        end_time_reordering = time.time()
        print(f"Time taken for reordering rules: {end_time_reordering - start_time_reordering:.2f} seconds")

class RuleProcessor:
    @staticmethod
    def is_rule_order_correct(current_rules, desired_rules):
        """
        Check if the order of rules in current_rules matches the order in desired_rules.
        """
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
        all_objects = self.api_handler.list(endpoint, self.folder_scope, limit, position)
        return set(o['name'] for o in all_objects)

    def fetch_rules(self, obj_type, limit='10000', position=''):
        endpoint = obj_type._endpoint

        all_objects = self.api_handler.list(endpoint, self.folder_scope, limit, position)
        return [o for o in all_objects if 'name' in o and 'folder' in o]

    def process_objects(self, parsed_data, folder_scope, device_group_name, max_workers=8, limit='10000'):
        # List current objects in SCM
        current_objects = self.get_current_objects(self.obj_types, max_workers=max_workers, limit=limit)

        # Get new entries based on parsed data and current SCM objects
        new_entries = self.get_new_entries(parsed_data, current_objects)

        # Post new entries to SCM
        self.post_new_entries(new_entries, folder_scope, device_group_name)

    def get_current_objects(self, obj_types, max_workers=6, limit='10000', **kwargs):
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
        # This matches the API Endpoint name as a Key to use for get_new_entries to match parsed_data_key
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
