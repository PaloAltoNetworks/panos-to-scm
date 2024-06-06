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
    # Setting up the logging configuration
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    
    # Log rotation setup: Rotates every midnight, keeps last 2 days of logs
    handler = TimedRotatingFileHandler('debug-log.txt', utc=True, when="midnight", interval=1, backupCount=1)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

    # Console handler to print INFO and above level logs to the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

def get_xml_file_path(config, logger):
    # Ask the user if they want to retrieve a new config from Palo Alto NGFW
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
    # Initialize and authenticate the API session
    session = PanApiSession()
    session.authenticate()
    return session

def setup_scm_object_manager(session, configure, obj_types, sec_obj, nat_obj, folder_scope):
    # Setup the SCMObjectManager with the necessary parameters
    return SCMObjectManager(session, folder_scope, configure, obj, obj_types, sec_obj, nat_obj)

def run_selected_objects(parsed_data, scm_obj_manager, folder_scope, device_group_name, obj_type):
    # Function to process the selected object type
    obj_type_name = obj_type.__name__
    logger.info(f"Looking for key '{obj_type_name}' in parsed_data.")
    
    if obj_type_name not in parsed_data:
        logger.warning(f"Key '{obj_type_name}' not found in parsed_data. Available keys: {list(parsed_data.keys())}")
        return

    logger.info(f"Processing object type: {obj_type_name}")
    scm_obj_manager.process_objects({obj_type_name: parsed_data[obj_type_name]}, folder_scope, device_group_name)

def main(config, run_object=None):
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

        if run_object:
            logger.info(f'Running specific object: {run_object}')
            objects_to_run = [obj for obj in config.obj_types if obj.__name__ == run_object]
            if not objects_to_run:
                logger.error(f"No object found with the name {run_object}")
            else:
                # Filter parsed_data to include only the selected object type
                filtered_parsed_data = {k: v for k, v in parsed_data.items() if k == run_object}
                scm_obj_manager = setup_scm_object_manager(api_session, configure, objects_to_run, config.sec_obj, config.nat_obj, folder_scope)
                for obj_to_run in objects_to_run:
                    run_selected_objects(filtered_parsed_data, scm_obj_manager, folder_scope, device_group_name, obj_to_run)
        else:
            scm_obj_manager = setup_scm_object_manager(api_session, configure, config.obj_types, config.sec_obj, config.nat_obj, folder_scope)
            scm_obj_manager.process_objects(parsed_data, folder_scope, device_group_name, max_workers=6)
            scm_obj_manager.process_security_rules(api_session, config.sec_obj, parsed_data, xml_file_path, limit=config.limit)
            scm_obj_manager.process_nat_rules(api_session, config.nat_obj, parsed_data, xml_file_path, limit=config.limit)

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
    
    parser = argparse.ArgumentParser(description="Run specific objects in the project")
    parser.add_argument('-o', '--object', type=str, help="Specify the object to run")
    args = parser.parse_args()
    
    main(config, run_object=args.object)
