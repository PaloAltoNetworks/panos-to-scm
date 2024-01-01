# main.py

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

import os
import json
import time
import xml.etree.ElementTree as ET
import logging
from log_module.scm_logging import setup_logging, mark_start_of_run_in_log, print_warnings_and_errors_from_log
### Start Logging
setup_logging()
from parse import parse_panosxml2
from dotenv import load_dotenv
### Load env variables from .env file
load_dotenv()
from api.token_utils import obtain_api_token
from scm.post_utils import create_objects

def process_entries(scope, entries, create_func, entry_type, client_id, client_secret, tsg_id, max_workers, object_type, extra_query_params=''):
    if not entries:
        print("No entries to process.")
        return

    initial_entry_count = len(entries)
    print(f"Processing {len(entries)} {entry_type} entries in parallel.")
    logging.info(f"Processing {len(entries)} {entry_type} entries in parallel.")
    created_count, exists_count, error_count = 0, 0, 0
    error_objects = []

    results = create_func(scope, 0, object_type, entries, client_id, client_secret, tsg_id, max_workers=max_workers, extra_query_params=extra_query_params)
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
    client_id = os.getenv('client_id')
    client_secret = os.getenv('client_secret')
    tsg_id = os.getenv('tsg_id')
    token_file = "token_cache.txt" ###Current iteration uses this file.. Will update eventually

    ###max_workers is used for parallel processing of API request - speed things along
    max_workers = 3 ##Careful as this can cause API rate limiting blockage by API endpoint... 3 seems to be a good rate limiter

    ### XML FilePath
    xml_file_path = 'example-config.xml'  # Update with your XML file - current supports Panorama and Local FW configuration

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
            scope = confirm_folder
            config_type = 'panorama/device-group'
        else:  # Assume shared if not device-group
            confirm_global = input("Do you want these objects/policies to end up in the Global Folder on SCM? yes/no: ").strip().lower()
            scope = "All" if confirm_global == 'yes' else input('Enter folder name: ').strip()
            config_type = 'panorama/shared'
    else:
        # Local configuration
        confirm_folder = input('What folder do you want the objects/policies to end up in? \n Use All for "Global" -Example "US-East-DC1" This is Case Sensitive: ').strip()
        scope = confirm_folder
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
    
    security_rule_post_entries = []
    if config_type == 'panorama/device-group':
        security_rule_post_entries = parse_panosxml2.parse_security_post_rules_entries(xml_file_path, config_type, device_group_name)
    
    nat_rule_pre_entries = parse_panosxml2.parse_nat_pre_rules_entries(xml_file_path, config_type, device_group_name)

    nat_rule_post_entries = []
    if config_type == 'panorama/device-group':
        nat_rule_post_entries = parse_panosxml2.parse_nat_post_rules_entries(xml_file_path, config_type, device_group_name)
    
    ### Process each type of entry in sequence

    """
    I suggest uncommenting a few of the process_entries at a time to verify the syntax is correct, etc etc etc
    """  
    process_entries(scope, edl_data_entries, create_objects, "EDL objects", client_id, client_secret, tsg_id, max_workers, object_type='external-dynamic-lists?', extra_query_params='')

    process_entries(scope, url_categories, create_objects, "url-categories", client_id, client_secret, tsg_id, max_workers, object_type='url-categories?', extra_query_params='')

    process_entries(scope, url_profiles, create_objects, "url-profiles", client_id, client_secret, tsg_id, max_workers, object_type='url-access-profiles?', extra_query_params='')

    process_entries(scope, vulnerability_profiles, create_objects, "vulnerability-profiles", client_id, client_secret, tsg_id, max_workers, object_type='vulnerability-protection-profiles?', extra_query_params='')

    process_entries(scope, spyware_profiles, create_objects, "anti-spyware profiles", client_id, client_secret, tsg_id, max_workers, object_type='anti-spyware-profiles?', extra_query_params='')

    process_entries(scope, virus_profiles, create_objects, "anti-virus profiles", client_id, client_secret, tsg_id, max_workers, object_type='wildfire-anti-virus-profiles?', extra_query_params='')

    process_entries(scope, profile_group_entries, create_objects, "profile groups", client_id, client_secret, tsg_id, max_workers, object_type='profile-groups?', extra_query_params='')

    process_entries(scope, tag_entries, create_objects, "tag objects", client_id, client_secret, tsg_id, max_workers, object_type='tags?', extra_query_params='')
    
    process_entries(scope, address_entries, create_objects, 'address objects', client_id, client_secret, tsg_id, max_workers, object_type='addresses?', extra_query_params='')
    
    process_entries(scope, address_group_entries, create_objects, "address-group objects", client_id, client_secret, tsg_id, max_workers, object_type='address-groups?', extra_query_params='')
    
    process_entries(scope, service_entries, create_objects, "service objects", client_id, client_secret, tsg_id, max_workers, object_type='services?', extra_query_params='')
    
    process_entries(scope, service_group_entries, create_objects, "service-group objects", client_id, client_secret, tsg_id, max_workers, object_type='service-groups?', extra_query_params='')
    
    process_entries(scope, app_filter_entries, create_objects, "application-filter objects", client_id, client_secret, tsg_id, max_workers, object_type='application-filters?', extra_query_params='')
    
    process_entries(scope, application_group_entries, create_objects, "application-groups objects", client_id, client_secret, tsg_id, max_workers, object_type='application-groups?', extra_query_params='')    
    
    process_entries(scope, security_rule_pre_entries, create_objects, "security rules", client_id, client_secret, tsg_id,  object_type='security-rules?', max_workers=1, extra_query_params="pre") ###### Setting max_workers=1 as security rule sequencing is important (i.e. the rules need to be in proper ordering)
    
    if security_rule_post_entries:
        process_entries(scope, security_rule_post_entries, create_objects, "security rules", client_id, client_secret, tsg_id,  object_type='security-rules?', max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as security rule sequencing is important (i.e. the rules need to be in proper ordering)

    """
    Uncomment the following NAT rule lines when ever feature added to the SCM API
    """  

    # process_entries(scope, nat_rule_pre_entries, create_objects, "nat rules", client_id, client_secret, tsg_id, object_type='nat-rules?', max_workers=1, extra_query_params="pre") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

    # if nat_rule_post_entries:
    #     process_entries(scope, nat_rule_post_entries, create_objects, "nat rules", client_id, client_secret, tsg_id, 'nat-rules?', max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

if __name__ == "__main__":
    start_position = mark_start_of_run_in_log('debug-log.txt')
    main()
    print_warnings_and_errors_from_log('debug-log.txt', start_position)
    print("Script finished! Check the terminal for warnings and errors.\nCheck debug-log.txt for further debug logs")
