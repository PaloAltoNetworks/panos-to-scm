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
import logging
from log_module import SCMLogger
from parse.parse_panos import XMLParser
from api import PanApiSession
from scm import PanApiHandler
from scm.process import Processor
import scm.obj as obj

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
    xml_file_path = 'pa-440.xml'  # Update with your XML file - current supports Panorama and Local FW configuration
    
    # Create an instance of XMLParser
    folder_scope, config_type, device_group_name = conf.parse_config_and_set_scope(xml_file_path)
    print(folder_scope, config_type, device_group_name)
    xml_parser = XMLParser(xml_file_path, config_type, device_group_name)

    # Parse all data using a single method call
    parsed_data = xml_parser.parse_all()
    
    ### Parse individual methods if preferred such as below
    # url_categories = xml_parser.url_category_entries()
    # url_profiles = xml_parser.url_profiles_entries()

    """
    I suggest commenting a few of the post_entries at a time to verify the syntax is correct, etc etc etc
    """

    entry_types = [
        (parsed_data['edl_entries'], obj.ExternalDynamicList),
        (parsed_data['url_categories'], obj.URLCategory),
        (parsed_data['url_profiles'], obj.URLAccessProfile),
        (parsed_data['vulnerability_profiles'], obj.VulnerabilityProtectionProfile),
        (parsed_data['spyware_profiles'], obj.AntiSpywareProfile),
        (parsed_data['antivirus_profiles'], obj.WildFireAntivirusProfile),
        (parsed_data['profile_groups'], obj.ProfileGroup),
        (parsed_data['tags'], obj.Tag),
        (parsed_data['addresses'], obj.Address),
        (parsed_data['address_groups'], obj.AddressGroup),
        (parsed_data['service_entries'], obj.Service),
        (parsed_data['service_groups'], obj.ServiceGroup),
        (parsed_data['application_filters'], obj.ApplicationFilter),
        (parsed_data['application_groups'], obj.ApplicationGroup)
    ]

    for entries, obj_class in entry_types:
        conf.post_entries(folder_scope, entries, obj_class, extra_query_params='')

    #Policies we are are going to do little different - since we'll be checking if they exist
    security_rule_pre_entries = parsed_data['security_pre_rules']
    # print(f'Current Palo pre-rules: {security_rule_pre_entries}')

    # # Retrieve current security rules before creating new ones
    security_rule_obj = obj.SecurityRule(api_handler)
    all_rules_pre = security_rule_obj.list_security_rules(folder_scope, limit=10000, position='pre')

    # # Filter out rules that do not belong to the specific folder_scope
    current_rules_pre = [rule for rule in all_rules_pre if rule['folder'] == folder_scope]
    # print(f'Current SCM pre-rules: {current_rules_pre}')

    # Extract rule names from current rules data
    current_rule_names_pre = set(rule['name'] for rule in current_rules_pre)

    # Identify new rules that need to be created
    rules_to_create_pre = [rule for rule in security_rule_pre_entries if rule['name'] not in current_rule_names_pre]
    print(f'Rules that need to be added to SCM: {rules_to_create_pre}')

    #Process new security rules for creation
    if rules_to_create_pre:
        '''max_workers is used for parallel processing of API request - speed things along'''
        conf.set_max_workers(4) ###Careful as this can cause API rate limiting blockage by API endpoint... 5 seems to be a rate for posting security policies###
        conf.post_entries(folder_scope, rules_to_create_pre, obj.SecurityRule, extra_query_params="?position=pre")
    else:
        message = f"No new pre-rules to create from XML: {xml_file_path}"
        if device_group_name:
            message += f" (Device Group: {device_group_name})"
        message += f" for SCM Folder: {folder_scope}."
        print(message)
        logging.info(message)

    # # Track and resolve if the rules are in the correct order
    conf.set_max_workers(4) ###Careful as this can cause API rate limiting blockage by API endpoint... 5 seems to be a rate for re-ordering security policies###
    conf.check_and_reorder_rules(security_rule_obj, folder_scope, security_rule_pre_entries, position='pre')

    # if security_rule_post_entries:
    #     post_entries(folder_scope, security_rule_post_entries, create_objects, session, object_type='security-rules?', max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as security rule sequencing is important (i.e. the rules need to be in proper ordering)

    """
    Uncomment the following NAT rule lines when ever feature added to the SCM API
    """  

    # post_entries(folder_scope, nat_rule_pre_entries, create_objects, session, object_type='nat-rules?', max_workers=1, extra_query_params="pre") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

    # if nat_rule_post_entries:
    #     post_entries(folder_scope, nat_rule_post_entries, create_objects, session, object_type='nat-rules?', max_workers=1, extra_query_params="post") ###### Setting max_workers=1 as nat rule sequencing is important (i.e. the rules need to be in proper ordering)

    end_time = time.time()  # End timing
    total_time = end_time - start_time
    print(f"Script execution time: {total_time:.2f} seconds")


if __name__ == "__main__":
    start_position = SCMLogger().mark_start_of_run_in_log()
    main()
    SCMLogger().print_warnings_and_errors_from_log()
    print("Script finished! Check the terminal for warnings and errors.\nCheck debug-log.txt for further debug logs")
