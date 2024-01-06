# /project/main.py

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

import time
import xml.etree.ElementTree as ET
import logging
from concurrent.futures import ThreadPoolExecutor
from log_module import SCMLogger
from parse import parse_panosxml2
from api import PanApiSession
from scm import PanApiHandler
import scm.obj as obj

# Setup SCMLogger
logger = SCMLogger()
# Start Logging
logger.setup_logging()
# Mark the start of the run in the log
start_position = logger.mark_start_of_run_in_log()


def process_entries(api_handler, folder_scope, entries, entry_type, max_workers, obj_class, extra_query_params=''):
    if not entries:
        print("No entries to process.")
        return

    initial_entry_count = len(entries)
    print(f"Processing {len(entries)} {entry_type} entries in parallel.")
    logging.info(f"Processing {len(entries)} {entry_type} entries in parallel.")
    created_count, exists_count, error_count = 0, 0, 0
    error_objects = []

    endpoint = obj_class.get_endpoint() + extra_query_params
    results = api_handler.create_objects(folder_scope, 0, endpoint, entries, max_workers)
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
    return created_count, exists_count, error_count

def rearrange_rules(security_rule_obj, folder_scope, original_rules, current_rules, max_workers):
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

        with ThreadPoolExecutor(max_workers) as executor:
            print(f'Currently utilizing {int(max_workers)} wokers.')
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

def main():
    ##time this script
    start_time = time.time()  # Start timing

    ##Authenticate
    session = PanApiSession()
    session.authenticate()
    api_handler = PanApiHandler(session)

    ### XML FilePath
    xml_file_path = 'example.xml'  # Update with your XML file - current supports Panorama and Local FW configuration

    # Load and parse the XML file to determine configuration type
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    # Check for the existence of the Panorama device-group XPath
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
        else:  # Assume shared if not device-group
            confirm_global = input("Do you want these objects/policies to end up in the Global Folder on SCM? yes/no: ").strip().lower()
            folder_scope = "All" if confirm_global == 'yes' else input('Enter folder name: ').strip()
            config_type = 'panorama/shared'
    else:
        # Local configuration
        confirm_folder = input('What folder do you want the objects/policies to end up in? \n Use All for "Global" -Example "US-East-DC1" This is Case Sensitive: ').strip()
        folder_scope = confirm_folder
        config_type = 'local'
    
    ### Parse XML file for different object types ####
    """
    I suggest uncommenting the print below one at a time to verify data is actually parsed
    do this before uncommenting and calling the process_entries further down
    """    
    url_categories = parse_panosxml2.parse_url_category_entries(xml_file_path, config_type, device_group_name)
    
    url_profiles = parse_panosxml2.parse_url_profiles_entries(xml_file_path, config_type, device_group_name)
    
    vulnerability_profiles = parse_panosxml2.parse_vulnerability_profiles_entries(xml_file_path, config_type, device_group_name)
    
    spyware_profiles = parse_panosxml2.parse_spyware_profiles_entries(xml_file_path, config_type, device_group_name)
    
    virus_profiles = parse_panosxml2.parse_antivirus_profiles_entries(xml_file_path, config_type, device_group_name)
    
    profile_group_entries = parse_panosxml2.parse_profile_group_entries(xml_file_path, config_type, device_group_name)
    
    tag_entries = parse_panosxml2.parse_tag_entries(xml_file_path, config_type, device_group_name)
    
    address_entries = parse_panosxml2.parse_address_entries(xml_file_path, config_type, device_group_name)
    
    address_group_entries = parse_panosxml2.parse_address_group_entries(xml_file_path, config_type, device_group_name)
    
    service_entries = parse_panosxml2.parse_service_entries(xml_file_path, config_type, device_group_name)
    
    service_group_entries = parse_panosxml2.parse_service_group_entries(xml_file_path, config_type, device_group_name)
    
    edl_data_entries = parse_panosxml2.parse_edl_entries(xml_file_path, config_type, device_group_name)
    
    app_filter_entries = parse_panosxml2.parse_application_filter_entries(xml_file_path, config_type, device_group_name)
    
    application_group_entries = parse_panosxml2.parse_application_group_entries(xml_file_path, config_type, device_group_name)
    
    security_rule_pre_entries = parse_panosxml2.parse_security_pre_rules_entries(xml_file_path, config_type, device_group_name)
    # print(security_rule_pre_entries)
    
    security_rule_post_entries = []
    if config_type == 'panorama/device-group':
        security_rule_post_entries = parse_panosxml2.parse_security_post_rules_entries(xml_file_path, config_type, device_group_name)
    
    nat_rule_pre_entries = parse_panosxml2.parse_nat_pre_rules_entries(xml_file_path, config_type, device_group_name)

    nat_rule_post_entries = []
    if config_type == 'panorama/device-group':
        nat_rule_post_entries = parse_panosxml2.parse_nat_post_rules_entries(xml_file_path, config_type, device_group_name)
    
    ### Process each type of entry in sequence

    # Start the timer for object creation
    start_time_objects = time.time()

    """
    I suggest commenting a few of the process_entries at a time to verify the syntax is correct, etc etc etc
    """  
    
    '''max_workers is used for parallel processing of API request - speed things along'''
    max_workers = 3 ##Careful as this can cause API rate limiting blockage by API endpoint... 3 seems to be a good rate limiter for objects

    process_entries(api_handler, folder_scope, edl_data_entries, "EDL objects", max_workers, obj.ExternalDynamicList)
    
    process_entries(api_handler, folder_scope, url_categories, "URL categories", max_workers, obj.URLCategory)

    process_entries(api_handler, folder_scope, url_profiles, "URL profiles", max_workers, obj.URLAccessProfile)

    process_entries(api_handler, folder_scope, vulnerability_profiles, "Vulnerability profiles", max_workers, obj.VulnerabilityProtectionProfile)

    process_entries(api_handler, folder_scope, spyware_profiles, "Spyware profiles", max_workers, obj.AntiSpywareProfile)

    process_entries(api_handler, folder_scope, virus_profiles, "WF-Antivirus profiles", max_workers, obj.WildFireAntivirusProfile)

    process_entries(api_handler, folder_scope, profile_group_entries, "Security Profile Groups", max_workers, obj.ProfileGroup)

    process_entries(api_handler, folder_scope, tag_entries, "Tag Objects", max_workers, obj.Tag)
    
    process_entries(api_handler, folder_scope, address_entries, "Address Objects", max_workers, obj.Address)

    process_entries(api_handler, folder_scope, address_group_entries, "Address Groups", max_workers, obj.AddressGroup)

    process_entries(api_handler, folder_scope, service_entries, "Service Objects", max_workers, obj.Service)

    process_entries(api_handler, folder_scope, service_group_entries, "Service Groups", max_workers, obj.ServiceGroup)

    process_entries(api_handler, folder_scope, app_filter_entries, "Application Filters", max_workers, obj.ApplicationFilter)

    process_entries(api_handler, folder_scope, application_group_entries, "Application Groups", max_workers, obj.ApplicationGroup)

    # Retrieve current security rules before creating new ones
    security_rule_obj = obj.SecurityRule(api_handler)
    current_rules_pre = security_rule_obj.list_security_rules(folder_scope, "pre")
    # print("Initial API Call Response:", current_rules_pre)

    # Extract rule names from current rules data
    current_rule_names_pre = set(rule['name'] for rule in current_rules_pre)

    # Identify new rules that need to be created
    rules_to_create_pre = [rule for rule in security_rule_pre_entries if rule['name'] not in current_rule_names_pre]

    # Process new security rules for creation
    '''max_workers is used for parallel processing of API request - speed things along'''
    max_workers = 8 ##Careful as this can cause API rate limiting blockage by API endpoint... 8 seems to be a good rate limiter for security policies

    if rules_to_create_pre:
        process_entries(api_handler, folder_scope, rules_to_create_pre, "security rules", max_workers, obj.SecurityRule, extra_query_params="?position=pre")

    # Print the time taken for object creation
    end_time_objects = time.time()
    print(f"Time taken for creating objects: {end_time_objects - start_time_objects:.2f} seconds\n")

    # Initialize a variable to track if the rules are in the correct order
    rules_in_correct_order = False
    last_known_order = None  # To track changes in rule order

    # Start the timer for rule reordering
    start_time_reordering = time.time()

    while not rules_in_correct_order:
        # Retrieve current security rules including newly created ones
        current_rules_pre_updated = security_rule_obj.list_security_rules(folder_scope, "pre")

        # Create a list of rule names for the current order, excluding 'default'
        current_order = [rule['name'] for rule in current_rules_pre_updated if rule['name'] != 'default']
        
        # Check for changes in the order
        if current_order == last_known_order:
            print("No change in rule order detected. Exiting reordering process.")
            break
        last_known_order = current_order

        # print(f'Current API order: {current_order}')

        # Ensure newly created rules are also considered in desired order
        desired_order = [rule['name'] for rule in security_rule_pre_entries if rule['name'] != 'default']
        # print(f'Desired order: {desired_order}')

        '''max_workers is used for parallel processing of API request - speed things along'''
        max_workers = 5 ##Careful as this can cause API rate limiting blockage by API endpoint... 5 seems to be a rate for re-ordering security policies
        if current_order != desired_order:
            print("Reordering rules now..")
            rearrange_rules(security_rule_obj, folder_scope, security_rule_pre_entries, current_rules_pre_updated, max_workers)
        else:
            rules_in_correct_order = True

    # if security_rule_post_entries:
    #     process_entries(folder_scope, security_rule_post_entries, create_objects, "security rules",  session, object_type='security-rules?', max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as security rule sequencing is important (i.e. the rules need to be in proper ordering)

    # Print the time taken for reordering
    end_time_reordering = time.time()
    print(f"Time taken for reordering rules: {end_time_reordering - start_time_reordering:.2f} seconds")

    """
    Uncomment the following NAT rule lines when ever feature added to the SCM API
    """  

    # process_entries(folder_scope, nat_rule_pre_entries, create_objects, "nat rules", session, object_type='nat-rules?', max_workers=1, extra_query_params="pre") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

    # if nat_rule_post_entries:
    #     process_entries(folder_scope, nat_rule_post_entries, create_objects, "nat rules", session, object_type='nat-rules?', max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

    end_time = time.time()  # End timing
    total_time = end_time - start_time
    print(f"Script execution time: {total_time:.2f} seconds")


if __name__ == "__main__":
    start_position = logger.mark_start_of_run_in_log()
    main()
    logger.print_warnings_and_errors_from_log(start_position)
    print("Script finished! Check the terminal for warnings and errors.\nCheck debug-log.txt for further debug logs")
