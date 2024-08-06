import logging
from logging.handlers import TimedRotatingFileHandler
import time
import os  # Import os module
from config import ConfigurationManager
from parse.parse_panos import XMLParser
from parse.parse_cisco import CiscoParser  # Cisco Parser added
from api import PanApiSession
from scm import PanApiHandler
from scm.process import Processor, SCMObjectManager
from api.palo_token import PaloToken
from panos import PaloConfigManager
import scm.obj as obj
import argparse

def setup_logging():
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    
    handler = TimedRotatingFileHandler('debug-log.txt', utc=True, when="midnight", interval=1, backupCount=1)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

def get_file_path_and_type(config, logger):
    if os.path.exists('cisco_config.txt'):
        config_choice = input("Do you want to parse Cisco or PANOS configuration? (cisco/panos): ").strip().lower()
    else:
        config_choice = 'panos'

    if config_choice == 'panos':
        user_choice = input("Do you want to retrieve new config from Palo Alto NGFW? (yes/no): ").strip().lower()
        file_path = "running_config.xml"

        if user_choice == 'yes':
            palo_token_manager = PaloToken()
            token = palo_token_manager.retrieve_token()
            palo_config_manager = PaloConfigManager(token, palo_token_manager.ngfw_url)
            running_config = palo_config_manager.get_running_config()

            with open(file_path, "w") as file:
                file.write(running_config)
            logger.info("New running configuration retrieved and saved.")
        else:
            file_path = config.xml_file_path
            logger.info(f"Using local XML file: {file_path}")
    else:
        file_path = config.cisco_file_path
        logger.info(f"Using Cisco configuration file: {file_path}")

    return file_path, config_choice

def initialize_api_session():
    session = PanApiSession()
    session.authenticate()
    return session

def setup_scm_object_manager(session, configure, obj_types, sec_obj, nat_obj, folder_scope):
    return SCMObjectManager(session, folder_scope, configure, obj, obj_types, sec_obj, nat_obj)

def run_selected_objects(parsed_data, scm_obj_manager, folder_scope, device_group_name, run_objects_list):
    selected_obj_types = [obj for obj in config.obj_types if obj.__name__ in run_objects_list]
    
    if not selected_obj_types:
        logger.warning(f"No valid objects found to run for {run_objects_list}")
        return
    
    scm_obj_manager.process_objects(parsed_data, folder_scope, device_group_name, max_workers=6, limit=config.limit)

def main(config, run_objects=None, run_security=False, run_app_override=False, run_decrypt_rules=False, run_nat=False, run_all=False):
    try:
        start_time = time.time()
        logger.info(f"Script started at {time.ctime(start_time)}")

        api_session = PanApiHandler(initialize_api_session())
        configure = Processor(api_session, config.max_workers, obj)

        file_path, config_type = get_file_path_and_type(config, logger)

        logger.info(f"File path: {file_path}, Config type: {config_type}")

        if config_type == 'panos':
            parser = XMLParser(file_path, config_type)
            folder_scope, config_type, device_group_name = parser.parse_config_and_set_scope(file_path)
            logger.info(f'Current SCM Folder: {folder_scope}, PANOS: {config_type}, Device Group: {device_group_name}')
            parser.config_type = config_type
            parser.device_group_name = device_group_name

            if run_objects:
                run_objects_list = run_objects.split(',')
                logger.info(f'Running specific objects: {run_objects_list}')
                parsed_data = parser.parse_specific_types(run_objects_list)
            else:
                run_objects_list = []  # Initialize as empty list
                parsed_data = parser.parse_all()
        else:
            parser = CiscoParser(file_path)
            parser.parse()
            parsed_data = parser.get_parsed_data()
            folder_scope = input("What folder is Cisco config going into? Case Sensitive: ").strip()
            device_group_name = None  # No device group in Cisco firewall
            run_objects_list = run_objects.split(',') if run_objects else []  # Initialize run_objects_list for Cisco

        logger.debug(f"Parsed data keys: {list(parsed_data.keys())}")

        selected_obj_types = [obj for obj in config.obj_types if obj.__name__ in run_objects_list] if run_objects else config.obj_types
        scm_obj_manager = setup_scm_object_manager(api_session, configure, selected_obj_types, config.sec_obj, config.nat_obj, folder_scope)

        if run_all:
            scm_obj_manager.process_objects(parsed_data, folder_scope, device_group_name, max_workers=6, limit=config.limit)
            scm_obj_manager.process_rules(config.sec_obj, parsed_data, file_path, limit=config.limit, rule_type='security')
            scm_obj_manager.process_rules(config.app_override_obj, parsed_data, file_path, limit=config.limit, rule_type='application-override')
            scm_obj_manager.process_rules(config.decryption_rule_obj, parsed_data, file_path, limit=config.limit, rule_type='decryption')
            configure.set_max_workers(1)  # Set max workers to 1 for NAT rules
            scm_obj_manager.process_rules(config.nat_obj, parsed_data, file_path, limit=config.limit, rule_type='nat')
        elif run_objects:
            run_selected_objects(parsed_data, scm_obj_manager, folder_scope, device_group_name, run_objects_list)
        else:
            if run_security:
                scm_obj_manager.process_rules(config.sec_obj, parsed_data, file_path, limit=config.limit, rule_type='security')
            elif run_app_override:
                scm_obj_manager.process_rules(config.app_override_obj, parsed_data, file_path, limit=config.limit, rule_type='application-override')
            elif run_decrypt_rules:
                scm_obj_manager.process_rules(config.decryption_rule_obj, parsed_data, file_path, limit=config.limit, rule_type='decryption')
            elif run_nat:
                configure.set_max_workers(1)  # Set max workers to 1 for NAT rules
                scm_obj_manager.process_rules(config.nat_obj, parsed_data, file_path, limit=config.limit, rule_type='nat')
            else:
                scm_obj_manager.process_objects(parsed_data, folder_scope, device_group_name, max_workers=6, limit=config.limit)

        end_time = time.time()
        logger.info(f"Script execution time: {end_time - start_time:.2f} seconds")
        logger.info(f"Script ended at {time.ctime(end_time)}")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
    
    complete_time = time.time()
    logger.info(f"Final Script execution time: {complete_time - begin_time:.2f} seconds")

if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)
    begin_time = time.time()
    config_manager = ConfigurationManager()
    config = config_manager.app_config

    obj_type_names = [obj.__name__ for obj in config.obj_types]
    obj_type_help = "Specify the objects to run, separated by commas. Supported objects: " + ", ".join(obj_type_names)
    
    parser = argparse.ArgumentParser(description="Run specific objects or policies in the project")
    parser.add_argument('-o', '--objects', type=str, help=obj_type_help)
    parser.add_argument('-s', '--security-rules', action='store_true', help="Run security rules")
    parser.add_argument('-p', '--app-override-rules', action='store_true', help="Run application override rules")
    parser.add_argument('-d', '--decryption-rules', action='store_true', help="Run decryption rules")
    parser.add_argument('-n', '--nat-rules', action='store_true', help="Run NAT rules")
    parser.add_argument('-a', '--all', action='store_true', help="Run all: Object types as well as Security, App Override, Decryption and NAT policies")
    args = parser.parse_args()
    
    main(config, run_objects=args.objects, run_security=args.security_rules, run_app_override=args.app_override_rules, run_decrypt_rules=args.decryption_rules, run_nat=args.nat_rules, run_all=args.all)
