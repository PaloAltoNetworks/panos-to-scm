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
from scm import PanApiHandler,SCMObjectManager
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

    # # Build Api Handler
    api_handler = PanApiHandler(session)
    configure = Processor(api_handler, max_workers)
    
    # # API Session used primarily for rule reordering
    rule_order = obj.SecurityRule(api_handler)

    ### XML FilePath
    xml_file_path = 'pa-440.xml'  # Update with your XML file - current supports Panorama and Local FW configuration
    # xml_file_path = 'ISC-0517-1315.xml'  # Update with your XML file - current supports Panorama and Local FW configuration

    # Create an instance of XMLParser
    parse = xml(xml_file_path, None)  # Initialize with None for config_type and device_group_name

    # Parse config and set scope
    folder_scope, config_type, device_group_name = parse.parse_config_and_set_scope(xml_file_path)
    print(f'Current SCM Folder:{folder_scope} using PANOS {config_type} and if Panorama, current Device Group:{device_group_name}')

    # Update XMLParser instance with the config type and device group name
    parse.config_type = config_type
    parse.device_group_name = device_group_name

    # Parse all data using a single method call
    parsed_data = parse.parse_all()

    # Call SCMObjectManager class with API Session and Obj endpoints
    scm_obj_manager = SCMObjectManager(api_handler, folder_scope, configure, obj)

    # List of object types to fetch
    obj_types = [obj.Tag, obj.Address, obj.AddressGroup, obj.Service, obj.ServiceGroup, obj.ExternalDynamicList, obj.URLCategory, obj.URLAccessProfile, obj.VulnerabilityProtectionProfile, obj.AntiSpywareProfile,
                 obj.WildFireAntivirusProfile, obj.ProfileGroup, obj.ApplicationFilter, obj.ApplicationGroup ]  # Add all required object types
    
    # Fetch current objects in SCM
    current_objects = scm_obj_manager.get_current_objects(obj_types, limit='10000')

    # Get new entries based on parsed data and current SCM objects
    new_entries = scm_obj_manager.get_new_entries(parsed_data, current_objects)

    # Post new entries to SCM
    scm_obj_manager.post_new_entries(new_entries, folder_scope, device_group_name)

    '''
    We're going to process security rules differently.. Mainly because we need to set the position(pre rulebase VS post rulebase)
    '''
    scm_obj_manager.process_security_rules(parsed_data, xml_file_path, rule_order, limit='10000')

    # # End of Script Timing
    end_time = time.time()  # End timing
    total_time = end_time - start_time
    print(f"Script execution time: {total_time:.2f} seconds")


if __name__ == "__main__":
    start_position = SCMLogger().mark_start_of_run_in_log()
    main()
    SCMLogger().print_warnings_and_errors_from_log()
    print("Script finished! Check the terminal for warnings and errors.\nCheck debug-log.txt for further debug logs")
