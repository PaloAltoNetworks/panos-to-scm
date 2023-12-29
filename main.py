# main.py

import os
import json
import logging
import time
from token_utils import obtain_api_token
from post_utils import create_url_categories, create_url_profiles, create_vulnerability_profiles, create_spyware_profiles, create_virus_profiles, create_profile_group_profiles, create_tag_objects, create_address_objects, create_address_group_objects, create_service_objects, create_service_group_objects, create_edl_objects, create_app_filter_objects, create_app_group_objects, create_security_rules, create_nat_rules
from parse_panosxml2 import parse_url_category_entries, parse_url_profiles_entries, parse_vulnerability_profiles_entries, parse_spyware_profiles_entries, parse_antivirus_profiles_entries, parse_profile_group_entries, parse_tag_entries, parse_address_entries, parse_address_group_entries, parse_service_entries, parse_service_group_entries, parse_edl_entries, parse_application_filter_entries, parse_application_group_entries, parse_security_pre_rules_entries, parse_security_post_rules_entries, parse_nat_pre_rules_entries, parse_nat_post_rules_entries

# Configure logging for this module
logging.basicConfig(filename='debug-log.txt', level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

def mark_start_of_run_in_log(log_file):
    # Check the current size of the log file
    if os.path.exists(log_file):
        position = os.path.getsize(log_file)
    else:
        position = 0

    # Write the start marker
    with open(log_file, 'a') as file:
        start_marker = f"\n===== Script Run Start: {time.ctime()} =====\n"
        file.write(start_marker)
    
    return position

def print_warnings_and_errors_from_log(log_file, start_position):
    try:
        with open(log_file, 'r') as file:
            file.seek(start_position)  # Jump to the start of the current run
            for line in file:
                if "WARNING" in line or "ERROR" in line or "CRITICAL" in line:
                    print(line.strip())
    except FileNotFoundError:
        print("Log file not found.")

def process_entries(scope, entries, create_func, entry_type, client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params=''):
    if not entries:
        print("No entries to process.")
        return

    initial_entry_count = len(entries)
    print(f"Processing {len(entries)} {entry_type} entries in parallel.")
    logging.info(f"Processing {len(entries)} {entry_type} entries in parallel.")
    created_count, exists_count, error_count = 0, 0, 0
    error_objects = []

    results = create_func(scope, 0, entries, client_id, client_secret, tsg_id, token_file, max_workers=max_workers, extra_query_params=extra_query_params)
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

def main():
    ### The below is used to pass to post_utils.py to obtain API token 
    client_id = 'example-service-acct@123456789.iam.panserviceaccount.com' ### Update this with your API Service account
    client_secret = os.environ.get('CLIENT_SECRET')
    if not client_secret:
        raise ValueError('''The CLIENT_SECRET environment variable is not set. Set environment variable for your secret key from your API service account
In MacOS/Linux "export CLIENT_SECRET=your-text-string" In Windows CMD "setx CLIENT_SECRET your-text-string"''')

    tsg_id = '123456789' ### Update this With your TSG ID
    token_file = "token_cache.txt" ###Current iteration uses this file.. Will update eventually

    ###max_workers is used for parallel processing of API request - speed things along
    max_workers = 3 ##Careful as this can cause API rate limiting blockage by API endpoint... 3 seems to be a good rate limiter

    ### XML FilePath

    xml_file_path = 'example-palo-config.xml'  ##Update with your XML file - current supports Panorama and Local FW configuration

    ###User input if XML file is Local Firewall XML, Panorama/Shared or Panorama/Device-group
    config_type = input("Enter the configuration type - type one of three options (local, panorama/shared, panorama/device-group): ").strip().lower()
    device_group_name = None

    ###Scope is the folder within CloudManager that objects/policies pulled from your PANOS XML with get placed into CloudManager.. Panorama/Shared automatically goes to "All" Folder(Global)
    
    if config_type == 'local':
            confirm_folder = input('What folder do you want the objects/policies to end up in? \n Use All for "Global" -Example "US-East-DC1" This is Case Sensitive: ').strip()
            scope = confirm_folder

    if config_type == 'panorama/device-group':
        device_group_name = input("Enter the device-group name: ").strip()
        confirm_folder = input('What folder do you want the objects/policies to end up in? \n Use All for "Global" -Example "US-East-DC1" This is Case Sensitive: ').strip() 
        scope = confirm_folder

    if config_type == 'panorama/shared':
        ###Confirm all scope for shared panorama objects/policies
        confirm_global = input("Do you want these objects/policies to end up in the Global Folder on SCM? yes/no: ").strip().lower()
        if confirm_global == 'yes':
            scope = "All"
        else:
            confirm_folder = input('What folder do you want the objects/policies to end up in? \n Use All for "Global" -Example "US-East-DC1" This is Case Sensitive: ').strip()
            scope = confirm_folder
    

    ### Parse XML file for different object types ####
    """
    I suggest uncommenting the print below one at a time to verify data is actually parsed
    do this before uncommenting and calling the process_entries further down
    """    
    url_categories = parse_url_category_entries(xml_file_path, config_type, device_group_name)
    
    url_profiles = parse_url_profiles_entries(xml_file_path, config_type, device_group_name)
    
    vulnerability_profiles = parse_vulnerability_profiles_entries(xml_file_path, config_type, device_group_name)
    
    spyware_profiles = parse_spyware_profiles_entries(xml_file_path, config_type, device_group_name)
    
    virus_profiles = parse_antivirus_profiles_entries(xml_file_path, config_type, device_group_name)
    
    profile_group_entries = parse_profile_group_entries(xml_file_path, config_type, device_group_name)
    
    tag_entries = parse_tag_entries(xml_file_path, config_type, device_group_name)
    
    address_entries = parse_address_entries(xml_file_path, config_type, device_group_name)
    
    address_group_entries = parse_address_group_entries(xml_file_path, config_type, device_group_name)
    
    service_entries = parse_service_entries(xml_file_path, config_type, device_group_name)
    
    service_group_entries = parse_service_group_entries(xml_file_path, config_type, device_group_name)
    
    edl_data_entries = parse_edl_entries(xml_file_path, config_type, device_group_name)
    
    app_filter_entries = parse_application_filter_entries(xml_file_path, config_type, device_group_name)
    
    application_group_entries = parse_application_group_entries(xml_file_path, config_type, device_group_name)
    
    security_rule_pre_entries = parse_security_pre_rules_entries(xml_file_path, config_type, device_group_name)
    
    security_rule_post_entries = []
    if config_type == 'panorama/device-group':
        security_rule_post_entries = parse_security_post_rules_entries(xml_file_path, config_type, device_group_name)
    
    nat_rule_pre_entries = parse_nat_pre_rules_entries(xml_file_path, config_type, device_group_name)

    nat_rule_post_entries = []
    if config_type == 'panorama/device-group':
        nat_rule_post_entries = parse_nat_post_rules_entries(xml_file_path, config_type, device_group_name)
    

    ### Process each type of entry in sequence

    """
    I suggest uncommenting a few of the process_entries at a time to verify the syntax is correct, etc etc etc
    """  
    process_entries(scope, edl_data_entries, create_edl_objects, "EDL objects", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')

    process_entries(scope, url_categories, create_url_categories, "url-categories", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')

    process_entries(scope, url_profiles, create_url_profiles, "url-profiles", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')

    process_entries(scope, vulnerability_profiles, create_vulnerability_profiles, "vulnerability-profiles", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')

    process_entries(scope, spyware_profiles, create_spyware_profiles, "anti-spyware profiles", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')

    process_entries(scope, virus_profiles, create_virus_profiles, "anti-virus profiles", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')

    process_entries(scope, profile_group_entries, create_profile_group_profiles, "profile groups", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')

    process_entries(scope, tag_entries, create_tag_objects, "tag objects", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')
    
    process_entries(scope, address_entries, create_address_objects, 'address objects', client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')
    
    process_entries(scope, address_group_entries, create_address_group_objects, "address-group objects", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')
    
    process_entries(scope, service_entries, create_service_objects, "service objects", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')
    
    process_entries(scope, service_group_entries, create_service_group_objects, "service-group objects", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')
    
    process_entries(scope, app_filter_entries, create_app_filter_objects, "application-filter objects", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')
    
    process_entries(scope, application_group_entries, create_app_group_objects, "application-groups objects", client_id, client_secret, tsg_id, token_file, max_workers, extra_query_params='')    
    
    process_entries(scope, security_rule_pre_entries, create_security_rules, "security rules", client_id, client_secret, tsg_id, token_file, max_workers=1, extra_query_params="pre") ###### Setting max_workers=1 as security rule sequencing is important (i.e. the rules need to be in proper ordering)
    
    if security_rule_post_entries:
        process_entries(scope, security_rule_post_entries, create_security_rules, "security rules", client_id, client_secret, tsg_id, token_file, max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as security rule sequencing is important (i.e. the rules need to be in proper ordering)


    # Uncomment the following NAT rule lines when ever added to the API
    # process_entries(scope, nat_rule_pre_entries, create_nat_rules, "nat rules", client_id, client_secret, tsg_id, max_workers=1, extra_query_params="pre") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

    # if nat_rule_pre_entries:
    #     process_entries(scope, nat_rule_post_entries, create_nat_rules, "nat rules", client_id, client_secret, tsg_id, max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

if __name__ == "__main__":
    start_position = mark_start_of_run_in_log('debug-log.txt')
    main()
    print_warnings_and_errors_from_log('debug-log.txt', start_position)
    print("Script finished! Check the terminal for warnings and errors.\nCheck debug-log.txt for further debug logs")