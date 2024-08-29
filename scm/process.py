import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Tuple, Dict

class Processor:
    def __init__(self, api_handler, max_workers: int, obj_module, scm_object_manager):
        self.api_handler = api_handler
        self.max_workers = max_workers
        self.obj = obj_module
        self.scm_object_manager = scm_object_manager
        self.logger = logging.getLogger(__name__)

    def set_max_workers(self, new_max_workers: int):
        self.max_workers = new_max_workers

    def post_entries(self, scope_param, entries: List[Any], obj_type, extra_query_params: str) -> Tuple[int, int, int]:
        if not entries:
            self.logger.info("No entries to process.")
            return 0, 0, 0

        start_time = time.time()
        initial_entry_count = len(entries)
        endpoint_message = obj_type.get_endpoint().replace('/sse/config/v1/', '').replace('?', '')
        self.logger.info(f"Processing {initial_entry_count} {endpoint_message} entries in parallel.")

        endpoint = f"{obj_type.get_endpoint()}{extra_query_params}{scope_param}"
        results = self.create_objects(endpoint, entries)

        created_count, exists_count, error_count, error_objects = self.analyze_results(results)

        self.log_summary(initial_entry_count, created_count, exists_count, error_count, error_objects, endpoint_message, start_time)

        return created_count, exists_count, error_count

    def create_objects(self, endpoint: str, data: List[Any]) -> List[Dict[str, Any]]:
        self.logger.info(f'Running with {self.max_workers} workers.')
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.api_handler.post, endpoint, item, retries=2, delay=0.5): item for item in data}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    if result.get('status') == 'success':
                        if result.get('message') == 'Object processed':
                            self.logger.info(f"Object '{result.get('name')}' created successfully.")
                        else:
                            self.logger.info(f"Object '{result.get('name')}' already exists.")
                    else:
                        self.logger.error(f"Error creating object '{futures[future].get('name')}': {result.get('message')}")
                except Exception as e:
                    self.logger.error(f"Error processing object: {e}")
        return results

    def analyze_results(self, results: List[Dict[str, Any]]) -> Tuple[int, int, int, List[str]]:
        created_count = sum(1 for r in results if r.get('status') == 'success' and r.get('message') == 'Object processed')
        exists_count = sum(1 for r in results if r.get('status') == 'success' and r.get('message') != 'Object processed')
        error_count = sum(1 for r in results if r.get('status') == 'error creating object')
        error_objects = [r.get('name') for r in results if r.get('status') == 'error creating object']
        return created_count, exists_count, error_count, error_objects

    def log_summary(self, initial_count: int, created_count: int, exists_count: int, error_count: int, error_objects: List[str], message: str, start_time: float):
        processing_time = time.time() - start_time
        summary = (
            f"The processing of {message} is complete.\n"
            f"Summary: {created_count} created, {exists_count} already existed, {error_count} errors.\n"
            f"Initial Object/Policy count: {initial_count}. Potential missing objects: {initial_count - (created_count + exists_count)}\n"
            f"Time taken for creating {message}: {processing_time:.2f} seconds\n"
        )
        if error_objects:
            summary += f"Objects with errors:\n{chr(10).join(f' - {error}' for error in error_objects)}\n"
        self.logger.info(summary)

    def reorder_rules(self, obj_type, endpoint, scope_param, original_rules, current_rules, limit, position):
        current_rule_ids = {rule['name']: rule['id'] for rule in current_rules}
        current_order = [rule['name'] for rule in current_rules]
        desired_order = [rule['name'] for rule in original_rules if rule['name'] in current_rule_ids]

        for _ in range(10000):  # Max 10000 attempts
            moves = []
            for i, rule_name in enumerate(desired_order[:-1]):
                if current_order.index(rule_name) > current_order.index(desired_order[i + 1]):
                    moves.append((
                        f"{endpoint}/{current_rule_ids[rule_name]}:move",
                        {"destination": "before", "rulebase": position, "destination_rule": current_rule_ids[desired_order[i + 1]]}
                    ))
                    self.logger.info(f"Prepared move: Rule '{rule_name}' before '{desired_order[i + 1]}'")

            if not moves:
                break

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self.api_handler.post, endpoint, move_data) for endpoint, move_data in moves]
                for future in as_completed(futures):
                    if future.result()['status'] != 'success':
                        self.logger.error(f"Error moving rule: {future.result()}")

            # Use the fetch_rules method from SCMObjectManager
            current_rules = self.scm_object_manager.fetch_rules(obj_type, limit=limit, position=position)
            current_order = [rule['name'] for rule in current_rules if rule['name'] != 'default']

        return current_rules  # Return the final state of the rules

    def check_and_reorder_rules(self, obj_type, scope_param, original_rules, limit, position):
        start_time = time.time()
        endpoint = obj_type.get_endpoint().replace('?', '')

        # Use the fetch_rules method to get the current rules
        current_rules = self.scm_object_manager.fetch_rules(obj_type, limit=limit, position=position)
        
        # Extract the current and desired order of rules, excluding 'default' rules
        current_order = [rule['name'] for rule in current_rules if rule['name'] != 'default']
        desired_order = [rule['name'] for rule in original_rules if rule['name'] != 'default']

        # Compare the current order with the desired order
        if current_order != desired_order:
            self.logger.info("Reordering rules now..")
            self.reorder_rules(obj_type, endpoint, scope_param, original_rules, current_rules, limit, position)

        self.logger.info(f"Time taken for reordering rules: {time.time() - start_time:.2f} seconds")


class SCMObjectManager:
    def __init__(self, api_handler, scope_param, obj_module, obj_types, sec_obj, nat_obj):
        self.api_handler = api_handler
        self.scope_param = scope_param
        self.configure = Processor(api_handler, 6, obj_module, self)
        self.obj = obj_module
        self.obj_types = obj_types
        self.sec_obj = sec_obj
        self.nat_obj = nat_obj        
        self.logger = logging.getLogger(__name__)
        self.scope_type, self.scope_value = self.parse_scope_param(scope_param)

    def parse_scope_param(self, scope_param):
        scope_type, scope_value = scope_param.lstrip('&').split('=')
        return scope_type, scope_value

    def fetch_objects(self, obj_type, limit='10000', position=''):
        endpoint = obj_type._endpoint
        max_limit = 5000  # Maximum limit allowed by the API - atleast for GET on address objects
        total_limit = int(limit)  # Convert the limit to an integer
        offset = 0  # Start offset for pagination
        all_objects = []  # Initialize list to store all fetched objects

        while offset < total_limit:
            # Calculate the limit for the current batch, ensuring it does not exceed max_limit
            current_limit = min(max_limit, total_limit - offset)
            params = {
                self.scope_type: self.scope_value,
                'limit': current_limit,
                'offset': offset  # Include the offset for pagination
            }
            if position:
                params['position'] = position
            
            # Fetch the current batch of objects
            current_objects = self.api_handler.get(endpoint, params=params)
            self.logger.debug(f'Fetched batch with offset {offset}: {current_objects}')

            # Add the current batch to the overall list
            all_objects.extend(current_objects)

            # Update offset for the next batch
            offset += current_limit
            
            # Debug statement to log the count of objects
            object_count = len([obj for obj in current_objects if 'name' in obj])
            self.logger.debug(f'Number of objects in current batch with "name" key: {object_count}')

            # Stop fetching if the number of objects returned is less than requested for the batch
            if len(current_objects) < current_limit:
                self.logger.debug('Fetched fewer objects than requested for the batch, no more objects to fetch.')
                break

        # Log the total number of objects fetched
        total_object_count = len(all_objects)
        self.logger.debug(f'Total number of objects fetched: {total_object_count}')

        return all_objects

    def fetch_rules(self, obj_type, limit='10000', position=''):
        rules = self.fetch_objects(obj_type, limit, position)
        return [o for o in rules if 'name' in o and ('folder' in o or 'snippet' in o)]

    def process_objects(self, parsed_data, scope_param, device_group_name, max_workers=6, limit='10000'):
        self.logger.info(f'Workers grabbing objects: {max_workers}')
        current_objects = self.get_current_objects(self.obj_types, max_workers, limit)
        new_entries, updated_entries = self.get_new_and_updated_entries(parsed_data, current_objects)

        if any(new_entries.values()):
            self.post_new_entries(new_entries, scope_param, device_group_name)

        self.update_existing_entries(updated_entries, scope_param, device_group_name, limit)

    def get_current_objects(self, obj_types, max_workers=6, limit='10000', **kwargs):
        self.logger.info(f"Running with {max_workers} workers.")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_obj_type = {
                executor.submit(
                    self.fetch_objects, 
                    obj_type, 
                    limit, 
                    **kwargs.get(obj_type.__name__, {})
                ): obj_type for obj_type in obj_types
            }
            return {obj_type: future.result() for future, obj_type in future_to_obj_type.items()}

    def get_new_and_updated_entries(self, parsed_data, current_objects):
        new_entries = {}
        updated_entries = {}
        for obj_type, current_set in current_objects.items():
            entry_type_name = obj_type.__name__
            parsed_data_key = self._generate_key_name(entry_type_name)
            if parsed_data_key not in parsed_data:
                self.logger.warning(f"Warning: Key '{parsed_data_key}' not found in parsed_data.")
                continue

            current_names = {o['name'] for o in current_set if isinstance(o, dict)}
            for parsed_obj in parsed_data[parsed_data_key]:
                name = parsed_obj['name']
                if name not in current_names:
                    new_entries.setdefault(entry_type_name, []).append(parsed_obj)
                else:
                    existing_obj = next(o for o in current_set if o['name'] == name)
                    parsed_obj_with_id = {**parsed_obj, 'id': existing_obj.get('id')}
                    if self.needs_update(parsed_obj_with_id, existing_obj):
                        resolved_entry = self.resolve_conflicts(parsed_obj_with_id, existing_obj)
                        updated_entries.setdefault(entry_type_name, []).append(resolved_entry)

        return new_entries, updated_entries

    def resolve_conflicts(self, new_object, current_object):
        normalized_new = self.normalize(new_object.copy())
        normalized_current = self.normalize(current_object.copy())

        if normalized_new == normalized_current:
            self.logger.debug(f"Objects '{new_object['name']}' are identical after normalization. Skipping conflict resolution.")
            return current_object

        print(f"Conflict detected for object '{new_object['name']}'")
        print(f"SCM Object: {normalized_current}")
        print(f"New Object: {normalized_new}")
        choice = input("Choose an action: [M]erge, [R]eplace, [C]reate new with appended name, [I]gnore (M/R/C/I): ").strip().upper()

        if choice == 'M':
            return self.merge_entries(new_object, current_object)
        elif choice == 'R':
            return new_object
        elif choice == 'C':
            new_object['name'] = f"{new_object['name']}_new"
            return new_object
        elif choice == 'I':
            self.logger.info(f"Ignoring conflict for object '{new_object['name']}'. No changes will be made.")
            return current_object
        else:
            print("Invalid choice. Ignoring conflict and making no changes.")
            return current_object

    @staticmethod
    def merge_entries(new_object, current_object):
        merged_object = current_object.copy()
        for key, value in new_object.items():
            if isinstance(value, list) and value:  # Only merge non-empty lists
                merged_object[key] = list(set(merged_object.get(key, []) + value))
            elif value not in (None, [], {}):  # Only update with non-empty values
                merged_object[key] = value
        return SCMObjectManager.normalize(merged_object)  # Normalize the result

    @staticmethod
    def needs_update(new_object, current_object):
        normalized_new = SCMObjectManager.normalize(new_object)
        normalized_current = SCMObjectManager.normalize(current_object)
        return normalized_new != normalized_current

    def update_existing_entries(self, updated_entries, scope_param, device_group_name, limit):
        for obj_type in self.obj_types:
            entry_type_name = obj_type.__name__
            if entry_type_name not in updated_entries:
                continue

            entry_class = getattr(self.obj, entry_type_name)
            for entry in updated_entries[entry_type_name]:
                object_id = entry.pop('id', None)
                if not object_id:
                    self.logger.warning(f"Warning: Object ID not found for {entry['name']} in {entry_type_name}. Skipping update.")
                    continue

                endpoint = f"{entry_class.get_endpoint().replace('?', '')}/{object_id}"
                
                # Parse the scope_param
                scope_type, scope_value = scope_param.lstrip('&').split('=')
                
                # Construct the params dictionary for the API call
                params = {scope_type: scope_value, 'limit': limit}
                
                current_objects = self.api_handler.get(entry_class.get_endpoint(), params=params)
                current_object = next((obj for obj in current_objects if obj['name'] == entry['name']), None)
                
                if not current_object:
                    self.logger.error(f"Current object '{entry['name']}' not found in SCM. Skipping update.")
                    continue

                if self.normalize(entry) != self.normalize(current_object):
                    self.logger.info(f"Updating {entry_type_name}: {entry['name']} at endpoint: {endpoint}")
                    result = self.api_handler.put(endpoint, entry)
                    if result['status'] == 'success':
                        self.logger.info(f"Updated {entry_type_name}: {entry['name']} with values: {entry}")
                    else:
                        self.logger.error(f"Failed to update {entry_type_name}: {entry['name']}, Reason: {result['message']}")
                else:
                    self.logger.info(f"No changes detected for {entry['name']}. Skipping update.")

    def _generate_key_name(self, entry_type_name):
        return entry_type_name.replace(' ', '-')

    def post_new_entries(self, new_entries, scope_param, device_group_name):
        for obj_type in self.obj_types:
            entry_type_name = obj_type.__name__
            if entry_type_name in new_entries and new_entries[entry_type_name]:
                entry_class = getattr(self.obj, entry_type_name)
                self.configure.post_entries(scope_param, new_entries[entry_type_name], entry_class, extra_query_params='')
            else:
                message = f"No new {entry_type_name} entries to create from parsed data"
                if device_group_name:
                    message += f" (Device Group: {device_group_name})"
                message += f" for SCM {self.scope_param.split('=')[0]}: {self.scope_param.split('=')[1]}."
                self.logger.info(message)

    def process_rules(self, rule_obj, parsed_data, scope_param, rule_type='security', limit='10000'):
        rule_data = {
            'security': ('security_pre_rules', 'security_post_rules'),
            'application-override': ('app_override_pre_rules', 'app_override_post_rules'),
            'decryption': ('decryption_pre_rules', 'decryption_post_rules'),
            'nat': ('nat_pre_rules', 'nat_post_rules')
        }
        pre_rules, post_rules = [parsed_data[key] for key in rule_data[rule_type]]

        current_rules_pre = self.fetch_rules(rule_obj, limit, position='pre')
        current_rules_post = self.fetch_rules(rule_obj, limit, position='post')
        
        current_rule_names_pre = {rule['name'] for rule in current_rules_pre}
        current_rule_names_post = {rule['name'] for rule in current_rules_post}
        
        rules_to_create_pre = [rule for rule in pre_rules if rule['name'] not in current_rule_names_pre]
        rules_to_create_post = [rule for rule in post_rules if rule['name'] not in current_rule_names_post]

        self.configure.set_max_workers(1 if rule_type == 'nat' else 6)

        rule_types = [
            (rules_to_create_pre, "position=pre", f"pre-{rule_type}-rules"),
            (rules_to_create_post, "position=post", f"post-{rule_type}-rules")
        ]

        for rules, extra_query_param, rule_type_name in rule_types:
            if rules:
                self.configure.post_entries(self.scope_param, rules, rule_obj, extra_query_params=extra_query_param)
            else:
                self.logger.info(f"No new {rule_type_name} to create from XML: {scope_param}")

        self.reorder_rules_if_needed(rule_obj, pre_rules, current_rules_pre, limit, position='pre')
        self.reorder_rules_if_needed(rule_obj, post_rules, current_rules_post, limit, position='post')

    def reorder_rules_if_needed(self, rule_obj, desired_rules, current_rules, limit, position):
        if not self.is_rule_order_correct(current_rules, desired_rules, limit):
            self.configure.check_and_reorder_rules(rule_obj, self.scope_param, desired_rules, limit='10000', position=position)

    @staticmethod
    def is_rule_order_correct(current_rules, desired_rules, limit):
        current_rule_names = [rule['name'] for rule in current_rules]
        desired_rule_names = [rule['name'] for rule in desired_rules]
        return current_rule_names == desired_rule_names

    @staticmethod
    def normalize(obj):
        def convert_to_int_if_possible(item):
            if isinstance(item, str):
                try:
                    return int(item)
                except ValueError:
                    return item
            return item

        def sort_key(item):
            if isinstance(item, (list, tuple)):
                return (0, tuple(sort_key(convert_to_int_if_possible(i)) for i in item))
            elif isinstance(item, dict):
                return (1, tuple(sorted((k, sort_key(v)) for k, v in item.items())))
            elif isinstance(item, (int, float)):
                return (2, item)
            elif isinstance(item, str):
                try:
                    return (2, int(item))
                except ValueError:
                    return (3, item)
            elif isinstance(item, bool):
                return (4, item)
            else:
                return (5, str(item))

        def sort_nested(item):
            if isinstance(item, dict):
                return {k: sort_nested(v) for k, v in sorted(item.items()) 
                        if v not in (None, [], {}) and not (k == 'threat_name' and v == 'any')}
            elif isinstance(item, list):
                return sorted((sort_nested(convert_to_int_if_possible(i)) for i in item if i not in (None, [], {})), key=sort_key)
            else:
                return convert_to_int_if_possible(item)

        normalized = {k: v for k, v in obj.items() 
                    if k not in {'folder', 'snippet', 'type', 'fqdn', 'protocol', 'description'} 
                    and v not in (None, [], {})
                    and not (k == 'threat_name' and v == 'any')}
        
        for key, value in normalized.items():
            if isinstance(value, (list, dict)):
                normalized[key] = sort_nested(value)
            else:
                normalized[key] = convert_to_int_if_possible(value)

        return dict(sorted(normalized.items(), key=lambda x: sort_key(x[1])))
