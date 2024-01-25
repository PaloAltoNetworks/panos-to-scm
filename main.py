# /project/main.py

import logging
from logging.handlers import TimedRotatingFileHandler
import time
from config import AppConfig
from parse.parse_panos import XMLParser
from api import PanApiSession
from scm import PanApiHandler
from scm.process import Processor, SCMObjectManager
from api.palo_token import PaloToken
from panos import PaloConfigManager
import scm.obj as obj

def setup_logging():
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    
    # Log rotation setup: Rotates every midnight, keeps last 2 days of logs
    handler = TimedRotatingFileHandler('debug-log.txt', utc= True, when="midnight", interval=1, backupCount=1)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)  # Captures and prints INFO, WARNING, ERROR, CRITICAL.
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

def get_xml_file_path(config, logger):
    user_choice = input("Do you want to retrieve new config from Palo Alto NGFW? (yes/no): ").strip().lower()
    xml_file_path = "running_config.xml"  # Default to the downloaded config

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

def setup_scm_object_manager(session, configure, obj_types, sec_obj, folder_scope):
    return SCMObjectManager(session, folder_scope, configure, obj, obj_types, sec_obj)

def main(config):
    setup_logging()
    logger = logging.getLogger(__name__)
    begin_time = time.time()
  
    try:
        start_time = time.time()
        logging.info(f"Script started at {time.ctime(start_time)}")

        api_handler = PanApiHandler(initialize_api_session())
        configure = Processor(api_handler, config.max_workers, obj)

        xml_file_path = get_xml_file_path(config, logger)

        parse = XMLParser(xml_file_path, None)
        folder_scope, config_type, device_group_name = parse.parse_config_and_set_scope(xml_file_path)
        logger.info(f'Current SCM Folder: {folder_scope}, PANOS: {config_type}, Device Group: {device_group_name}')
        
        parse.config_type = config_type
        parse.device_group_name = device_group_name
        parsed_data = parse.parse_all()

        scm_obj_manager = setup_scm_object_manager(api_handler, configure, config.obj_types, config.sec_obj, folder_scope)
        scm_obj_manager.process_objects(parsed_data, folder_scope, device_group_name, max_workers=6)
        scm_obj_manager.process_security_rules(api_handler, config.sec_obj, parsed_data, xml_file_path, limit=config.limit)

        end_time = time.time()
        logger.info(f"Script execution time: {end_time - start_time:.2f} seconds")
        logging.info(f"Script ended at {time.ctime(end_time)}")

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    
    complete_time = time.time()
    logger.info(f"Final Script execution time: {complete_time - begin_time:.2f} seconds")

if __name__ == "__main__":
    config = AppConfig()
    main(config)
