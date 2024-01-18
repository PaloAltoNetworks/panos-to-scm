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
from parse.parse_panos import XMLParser as xml
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
    configure = Processor(api_handler, max_workers)

    ### XML FilePath
    xml_file_path = 'pa-440.xml'  # Update with your XML file - current supports Panorama and Local FW configuration

    # Create an instance of XMLParser
    parse = xml(xml_file_path, None)  # Initialize with None for config_type and device_group_name

    # Parse config and set scope
    folder_scope, config_type, device_group_name = parse.parse_config_and_set_scope(xml_file_path)
    print(folder_scope, config_type, device_group_name)

    # Update XMLParser instance with the config type and device group name
    parse.config_type = config_type
    parse.device_group_name = device_group_name

    # Parse all data using a single method call
    parsed_data = parse.parse_all()
    
    ### Parse individual methods if preferred such as below
    # url_categories = parse.url_category_entries()
    # url_profiles = parse.url_profiles_entries()

    """
    I suggest commenting a few of the post_entries at a time to verify the syntax is correct, etc etc etc
    """
    # # Build the API Session for the API Endpoint
    tag_obj = obj.Tag(api_handler)
    addr_obj = obj.Address(api_handler)
    addr_grp_obj = obj.AddressGroup(api_handler)
    service_obj = obj.Service(api_handler)
    service_grp_obj = obj.ServiceGroup(api_handler)
    edl_obj = obj.ExternalDynamicList(api_handler)
    url_obj = obj.URLCategory(api_handler)
    url_prof_obj = obj.URLAccessProfile(api_handler)
    vuln_prof_obj = obj.VulnerabilityProtectionProfile(api_handler)
    spyware_obj = obj.AntiSpywareProfile(api_handler)
    virus_obj = obj.WildFireAntivirusProfile(api_handler)
    profileGroup_obj = obj.ProfileGroup(api_handler)
    appFilter_obj = obj.ApplicationFilter(api_handler)
    appGroup_obj = obj.ApplicationGroup(api_handler)
    security_rule_obj = obj.SecurityRule(api_handler)

    # # Get Current SCM Objects
    all_tag = tag_obj.list(folder_scope, position='', limit='10000')
    all_addr = addr_obj.list(folder_scope, position='', limit='10000')
    all_addr_grp = addr_grp_obj.list(folder_scope, position='', limit='10000')
    all_service = service_obj.list(folder_scope, position='', limit='10000')
    all_service_grp = service_grp_obj.list(folder_scope, position='', limit='10000')
    all_edl = edl_obj.list(folder_scope, position='', limit='10000')
    all_url = url_obj.list(folder_scope, position='', limit='10000')
    all_url_prof = url_prof_obj.list(folder_scope, position='', limit='1000')
    all_vuln_prof = vuln_prof_obj.list(folder_scope, position='', limit='1000')
    all_spyware_prof = spyware_obj.list(folder_scope, position='', limit='1000')
    all_virus_prof = virus_obj.list(folder_scope, position='', limit='1000')
    all_profile_group = profileGroup_obj.list(folder_scope, position='', limit='1000')
    all_app_filter = appFilter_obj.list(folder_scope, position='', limit='1000')
    all_app_group = appGroup_obj.list(folder_scope, position='', limit='1000')
    # print(all_profile_group)
    all_rules_pre = security_rule_obj.list(folder_scope, position='pre', limit='10000')
    
    current_scm_tag = set(tags['name'] for tags in all_tag)
    current_scm_addr = set((addr['name'], addr.get('ip_netmask') or addr.get('ip_range') or addr.get('fqdn')) for addr in all_addr)
    current_scm_addr_grp_names = set(addr_grp['name'] for addr_grp in all_addr_grp)
    current_scm_service = set(service['name'] for service in all_service)
    current_scm_service_grp = set(service['name'] for service in all_service_grp)
    current_scm_edl = set(edl['name'] for edl in all_edl)
    current_scm_url = set(url['name'] for url in all_url)
    current_scm_url_profile = set(url['name'] for url in all_url_prof)
    current_scm_vuln_profile = set(prof['name'] for prof in all_vuln_prof)
    current_scm_spy_profile = set(prof['name'] for prof in all_spyware_prof)
    current_scm_virus_profile = set(prof['name'] for prof in all_virus_prof)
    current_scm_profile_group = set(prof['name'] for prof in all_profile_group)
    current_scm_app_filter = set(app['name'] for app in all_app_filter)
    current_scm_app_group = set(app['name'] for app in all_app_group)
    
    # # Slightly different method for security rules
    current_rules_pre = [rule for rule in all_rules_pre if rule['folder'] == folder_scope]
    current_rule_names_pre = set(rule['name'] for rule in current_rules_pre)
    security_rule_pre_entries = parsed_data['security_pre_rules']
    rules_to_create_pre = [rule for rule in security_rule_pre_entries if rule['name'] not in current_rule_names_pre]

    '''Update parsed data to send to SCM for already existing items. This only currently matches:
    if 'name' and 'type' are 100% match at least for address objects. Otherwise, it'll attempt to create
    and exception raises that an object already exists
    '''

    new_tag = [tags for tags in parsed_data['tags'] if tags['name'] not in current_scm_tag]
    new_addr = [addr for addr in parsed_data['addresses'] if (addr['name'], addr.get('ip_netmask') or addr.get('ip_range') or addr.get('fqdn')) not in current_scm_addr]
    new_addr_grp = [addr_grp for addr_grp in parsed_data['address_groups'] if addr_grp['name'] not in current_scm_addr_grp_names]
    new_service = [service for service in parsed_data['service_entries'] if service['name'] not in current_scm_service]
    new_service_grp = [service for service in parsed_data['service_groups'] if service['name'] not in current_scm_service_grp]
    new_edl = [edl for edl in parsed_data['edl_entries'] if edl['name'] not in current_scm_edl]
    new_url = [url for url in parsed_data['url_categories'] if url['name'] not in current_scm_url]
    new_url_profile = [url for url in parsed_data['url_categories'] if url['name'] not in current_scm_url_profile]
    new_vuln_profile = [prof for prof in parsed_data['vulnerability_profiles'] if prof['name'] not in current_scm_vuln_profile]
    new_spyware_profile = [prof for prof in parsed_data['spyware_profiles'] if prof['name'] not in current_scm_spy_profile]
    new_virus_profile = [prof for prof in parsed_data['antivirus_profiles'] if prof['name'] not in current_scm_virus_profile]
    new_profile_group = [prof for prof in parsed_data['profile_groups'] if prof['name'] not in current_scm_profile_group]
    new_app_filter = [app for app in parsed_data['application_filters'] if app['name'] not in current_scm_app_filter]
    new_app_group = [app for app in parsed_data['application_groups'] if app ['name'] not in current_scm_app_group]

    entry_types = [
        (new_edl, obj.ExternalDynamicList),
        (new_url, obj.URLCategory),
        (new_url_profile, obj.URLAccessProfile),
        (new_vuln_profile, obj.VulnerabilityProtectionProfile),
        (new_spyware_profile, obj.AntiSpywareProfile),
        (new_virus_profile, obj.WildFireAntivirusProfile),
        (new_profile_group, obj.ProfileGroup),
        (new_tag, obj.Tag),
        (new_addr, obj.Address),
        (new_addr_grp, obj.AddressGroup),
        (new_service, obj.Service),
        (new_service_grp, obj.ServiceGroup),
        (new_app_filter, obj.ApplicationFilter),
        (new_app_group, obj.ApplicationGroup)
    ]

    for entries, obj_class in entry_types:
        configure.post_entries(folder_scope, entries, obj_class, extra_query_params='')

    #Process new security rules for creation
    if rules_to_create_pre:
        '''max_workers is used for parallel processing of API request - speed things along'''
        configure.set_max_workers(4) ###Careful as this can cause API rate limiting blockage by API endpoint... 4 seems to be a rate for posting security policies###
        configure.post_entries(folder_scope, rules_to_create_pre, obj.SecurityRule, extra_query_params="?position=pre")
    else:
        message = f"No new pre-rules to create from XML: {xml_file_path}"
        if device_group_name:
            message += f" (Device Group: {device_group_name})"
        message += f" for SCM Folder: {folder_scope}."
        print(message)
        logging.info(message)

    # Track and resolve if the rules are in the correct order
    configure.set_max_workers(4) ###Careful as this can cause API rate limiting blockage by API endpoint... 4 seems to be a rate for re-ordering security policies###
    configure.check_and_reorder_rules(security_rule_obj, folder_scope, security_rule_pre_entries, limit='10000', position='pre')

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
