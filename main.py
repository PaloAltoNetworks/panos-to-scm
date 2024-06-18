import logging
from logging.handlers import TimedRotatingFileHandler
import time
from config import ConfigurationManager
from parse.parse_panos import XMLParser
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

def get_xml_file_path(config, logger):
    user_choice = input("Do you want to retrieve new config from Palo Alto NGFW? (yes/no): ").strip().lower()
    xml_file_path = "running_config.xml"

    if user_choice == 'yes':
        palo_token_manager = PaloToken()
        token = palo_token_manager.retrieve_token()
        palo_config_manager = PaloConfigManager(token, palo_token_manager.ngfw_url)
        running_config = palo_config_manager.get_running_config()

        with open(xml_file_path, "w") as file:
            file.write(running_config)
        logger.info("New running configuration retrieved and saved.")
    else:
        xml_file_path = config.xml_file_path
        logger.info(f"Using local XML file: {xml_file_path}")

    return xml_file_path

def initialize_api_session():
    session = PanApiSession()
    session.authenticate()
    return session

def setup_scm_object_manager(session, configure, obj_types, sec_obj, nat_obj, folder_scope):
    return SCMObjectManager(session, folder_scope, configure, obj, obj_types, sec_obj, nat_obj)

def run_selected_objects(parsed_data, scm_obj_manager, folder_scope, device_group_name, obj_types):
    for obj_type in obj_types:
        obj_type_name = obj_type.__name__
        
        logger.info(f"Looking for key '{obj_type_name}' in parsed_data.")
        
        if obj_type_name not in parsed_data:
            logger.warning(f"Key '{obj_type_name}' not found in parsed_data. Available keys: {list(parsed_data.keys())}")
            continue

        logger.info(f"Processing object type: {obj_type_name}")
        scm_obj_manager.process_objects({obj_type_name: parsed_data[obj_type_name]}, folder_scope, device_group_name)

def main(config, run_objects=None, run_security=False, run_nat=False, run_all=False):
    try:
        start_time = time.time()
        logging.info(f"Script started at {time.ctime(start_time)}")

        api_session = PanApiHandler(initialize_api_session())
        configure = Processor(api_session, config.max_workers, obj)

        xml_file_path = get_xml_file_path(config, logger)

        parse = XMLParser(xml_file_path, None)
        folder_scope, config_type, device_group_name = parse.parse_config_and_set_scope(xml_file_path)
        logger.info(f'Current SCM Folder: {folder_scope}, PANOS: {config_type}, Device Group: {device_group_name}')
        
        parse.config_type = config_type
        parse.device_group_name = device_group_name
        parsed_data = parse.parse_all()
        logger.debug(f"Parsed data keys: {list(parsed_data.keys())}")

        scm_obj_manager = setup_scm_object_manager(api_session, configure, config.obj_types, config.sec_obj, config.nat_obj, folder_scope)

        if run_all:
            scm_obj_manager.process_objects(parsed_data, folder_scope, device_group_name, max_workers=6)
            scm_obj_manager.process_rules(config.sec_obj, parsed_data, xml_file_path, limit=config.limit, rule_type='security')
            configure.set_max_workers(1)  # Set max workers to 1 for NAT rules
            scm_obj_manager.process_rules(config.nat_obj, parsed_data, xml_file_path, limit=config.limit, rule_type='nat')
        elif run_objects:
            run_objects_list = run_objects.split(',')
            logger.info(f'Running specific objects: {run_objects_list}')
            for obj_name in run_objects_list:
                objects_to_run = [obj for obj in config.obj_types if obj.__name__ == obj_name]
                if not objects_to_run:
                    logger.error(f"No valid object found with the name {obj_name}")
                    continue
                filtered_parsed_data = {k: v for k, v in parsed_data.items() if k == obj_name}
                run_selected_objects(filtered_parsed_data, scm_obj_manager, folder_scope, device_group_name, objects_to_run)
        else:
            if run_security:
                scm_obj_manager.process_rules(config.sec_obj, parsed_data, xml_file_path, limit=config.limit, rule_type='security')
            elif run_nat:
                configure.set_max_workers(1)  # Set max workers to 1 for NAT rules
                scm_obj_manager.process_rules(config.nat_obj, parsed_data, xml_file_path, limit=config.limit, rule_type='nat')
            else:
                scm_obj_manager.process_objects(parsed_data, folder_scope, device_group_name, max_workers=6)

        end_time = time.time()
        logger.info(f"Script execution time: {end_time - start_time:.2f} seconds")
        logging.info(f"Script ended at {time.ctime(end_time)}")

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    
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
    
    parser = argparse.ArgumentParser(description="Run specific objects in the project")
    parser.add_argument('-o', '--objects', type=str, help=obj_type_help)
    parser.add_argument('-s', '--security-rules', action='store_true', help="Run security rules processing")
    parser.add_argument('-n', '--nat-rules', action='store_true', help="Run NAT rules processing")
    parser.add_argument('-a', '--all', action='store_true', help="Run all: objects, security rules, and NAT rules")
    args = parser.parse_args()
    
    main(config, run_objects=args.objects, run_security=args.security_rules, run_nat=args.nat_rules, run_all=args.all)
