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
from parse import parse_panosxml2 as parse
from api import PanApiSession
from scm import PanApiHandler
from scm.process import Processor
import scm.obj as obj

# Setup SCMLogger
logger = SCMLogger()
# Start Logging
logger.setup_logging()
# Mark the start of the run in the log
start_position = logger.mark_start_of_run_in_log()

def main():
    ##time this script
    start_time = time.time()  # Start timing

    '''max_workers is used for parallel processing of API request - speed things along'''
    max_workers = 3 ##Careful as this can cause API rate limiting blockage by API endpoint... 3 seems to be a good rate limiter for objects

    ##Authenticate
    session = PanApiSession()
    session.authenticate()
    api_handler = PanApiHandler(session)
    conf = Processor(api_handler, max_workers)

    ### XML FilePath
    xml_file_path = 'example.xml'  # Update with your XML file - current supports Panorama and Local FW configuration

    # Use Processor class to parse XML and determine configuration
    folder_scope, config_type, device_group_name = conf.parse_config_and_set_scope(xml_file_path)
    
    ### Parse XML file for different object types ####
    url_categories = parse.url_category_entries(xml_file_path, config_type, device_group_name)
    
    url_profiles = parse.url_profiles_entries(xml_file_path, config_type, device_group_name)
    
    vulnerability_profiles = parse.vulnerability_profiles_entries(xml_file_path, config_type, device_group_name)
    
    spyware_profiles = parse.spyware_profiles_entries(xml_file_path, config_type, device_group_name)
    
    virus_profiles = parse.antivirus_profiles_entries(xml_file_path, config_type, device_group_name)
    
    profile_group_entries = parse.profile_group_entries(xml_file_path, config_type, device_group_name)
    
    tag_entries = parse.tag_entries(xml_file_path, config_type, device_group_name)
    
    address_entries = parse.address_entries(xml_file_path, config_type, device_group_name)
    
    address_group_entries = parse.address_group_entries(xml_file_path, config_type, device_group_name)
    
    service_entries = parse.service_entries(xml_file_path, config_type, device_group_name)
    
    service_group_entries = parse.service_group_entries(xml_file_path, config_type, device_group_name)
    
    edl_data_entries = parse.edl_entries(xml_file_path, config_type, device_group_name)
    
    app_filter_entries = parse.application_filter_entries(xml_file_path, config_type, device_group_name)
    
    application_group_entries = parse.application_group_entries(xml_file_path, config_type, device_group_name)
    
    security_rule_pre_entries = parse.security_pre_rules_entries(xml_file_path, config_type, device_group_name)
    
    security_rule_post_entries = []
    if config_type == 'panorama/device-group':
        security_rule_post_entries = parse.security_post_rules_entries(xml_file_path, config_type, device_group_name)
    
    nat_rule_pre_entries = parse.nat_pre_rules_entries(xml_file_path, config_type, device_group_name)

    nat_rule_post_entries = []
    if config_type == 'panorama/device-group':
        nat_rule_post_entries = parse.nat_post_rules_entries(xml_file_path, config_type, device_group_name)
    
    ### Process each type of entry in sequence

    # Start the timer for object creation
    start_time_objects = time.time()

    """
    I suggest commenting a few of the post_entries at a time to verify the syntax is correct, etc etc etc
    """   

    conf.post_entries(folder_scope, edl_data_entries, "EDL objects", obj.ExternalDynamicList, extra_query_params='')
    
    conf.post_entries(folder_scope, url_categories, "URL categories", obj.URLCategory, extra_query_params='')

    conf.post_entries(folder_scope, url_profiles, "URL profiles", obj.URLAccessProfile, extra_query_params='')

    conf.post_entries(folder_scope, vulnerability_profiles, "Vulnerability profiles", obj.VulnerabilityProtectionProfile, extra_query_params='')

    conf.post_entries(folder_scope, spyware_profiles, "Spyware profiles", obj.AntiSpywareProfile, extra_query_params='')

    conf.post_entries(folder_scope, virus_profiles, "WF-Antivirus profiles", obj.WildFireAntivirusProfile, extra_query_params='')

    conf.post_entries(folder_scope, profile_group_entries, "Security Profile Groups", obj.ProfileGroup, extra_query_params='')

    conf.post_entries(folder_scope, tag_entries, "Tag Objects", obj.Tag, extra_query_params='')
    
    conf.post_entries(folder_scope, address_entries, "Address Objects", obj.Address, extra_query_params='')

    conf.post_entries(folder_scope, address_group_entries, "Address Groups", obj.AddressGroup, extra_query_params='')

    conf.post_entries(folder_scope, service_entries, "Service Objects", obj.Service, extra_query_params='')

    conf.post_entries(folder_scope, service_group_entries, "Service Groups", obj.ServiceGroup, extra_query_params='')

    conf.post_entries(folder_scope, app_filter_entries, "Application Filters", obj.ApplicationFilter, extra_query_params='')

    conf.post_entries(folder_scope, application_group_entries, "Application Groups", obj.ApplicationGroup, extra_query_params='')

    # Retrieve current security rules before creating new ones
    security_rule_obj = obj.SecurityRule(api_handler)
    current_rules_pre = security_rule_obj.list_security_rules(folder_scope, position='pre')
    # print("Initial API Call Response:", current_rules_pre)

    # Extract rule names from current rules data
    current_rule_names_pre = set(rule['name'] for rule in current_rules_pre)

    # Identify new rules that need to be created
    rules_to_create_pre = [rule for rule in security_rule_pre_entries if rule['name'] not in current_rule_names_pre]

    # Process new security rules for creation
    if rules_to_create_pre:
        '''max_workers is used for parallel processing of API request - speed things along'''
        max_workers = 5 ##Careful as this can cause API rate limiting blockage by API endpoint... 5 seems to be a rate for posting security policies        
        conf.post_entries(folder_scope, rules_to_create_pre, "security rules", obj.SecurityRule, extra_query_params="?position=pre")
    else:
        print(f'No new pre-rules to create from XML: {xml_file_path}:{device_group_name} for SCM Folder: {folder_scope}.')
        logging.info(f'No new pre-rules to create from XML: {xml_file_path}:{device_group_name} for SCM Folder: {folder_scope}.')

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
        conf = Processor(api_handler, max_workers)
        if current_order != desired_order:
            print("Reordering rules now..")
            conf.reorder_rules(security_rule_obj, folder_scope, security_rule_pre_entries, current_rules_pre_updated)
        else:
            rules_in_correct_order = True

    # if security_rule_post_entries:
    #     post_entries(folder_scope, security_rule_post_entries, create_objects, "security rules",  session, object_type='security-rules?', max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as security rule sequencing is important (i.e. the rules need to be in proper ordering)

    # Print the time taken for reordering
    end_time_reordering = time.time()
    print(f"Time taken for reordering rules: {end_time_reordering - start_time_reordering:.2f} seconds")

    """
    Uncomment the following NAT rule lines when ever feature added to the SCM API
    """  

    # post_entries(folder_scope, nat_rule_pre_entries, create_objects, "nat rules", session, object_type='nat-rules?', max_workers=1, extra_query_params="pre") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

    # if nat_rule_post_entries:
    #     post_entries(folder_scope, nat_rule_post_entries, create_objects, "nat rules", session, object_type='nat-rules?', max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

    end_time = time.time()  # End timing
    total_time = end_time - start_time
    print(f"Script execution time: {total_time:.2f} seconds")


if __name__ == "__main__":
    start_position = logger.mark_start_of_run_in_log()
    main()
    logger.print_warnings_and_errors_from_log(start_position)
    print("Script finished! Check the terminal for warnings and errors.\nCheck debug-log.txt for further debug logs")
