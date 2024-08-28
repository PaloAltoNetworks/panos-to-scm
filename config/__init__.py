import os
import sys
import yaml
import logging
import scm.obj as obj

class AppConfig:
    def __init__(self):
        self.max_workers = 4
        self.xml_file_path = 'running_config.xml'
        self.cisco_file_path = 'cisco_config.txt'
        self.limit = '100000'
        self.obj_types = [
            obj.Tag, obj.Application, obj.Address, obj.AddressGroup, obj.Service, 
            obj.ServiceGroup, obj.ExternalDynamicList, obj.URLCategory, 
            obj.URLAccessProfile, obj.VulnerabilityProtectionProfile, 
            obj.AntiSpywareProfile, obj.FileBlockingProfile,
            # obj.WildFireAntivirusProfile,
            obj.DNSSecurityProfile, obj.ProfileGroup, obj.ApplicationFilter, obj.ApplicationGroup,
            obj.Schedule, obj.DecryptionProfile, obj.HipObject, obj.HipProfile
        ]
        self.sec_obj = obj.SecurityRule
        self.nat_obj = obj.NatRule
        self.app_override_obj = obj.ApplicationOverrideRule
        self.decryption_rule_obj = obj.DecryptionRule

class ConfigurationManager:
    def __init__(self):
        self.config_file_path = os.path.expanduser('~/.panapi/config.yml')
        self.app_config = AppConfig()
        self.ensure_config_exists()
        self.check_for_default_settings()

    def ensure_config_exists(self):
        if not os.path.exists(self.config_file_path):
            self.create_default_config_file()

    def create_default_config_file(self):
        default_config = {
            "client_id": "enter-username",
            "client_secret": "xxxxxxxxxxxxxxxxxxxxxx",
            "tsg_id": "enter-unique-tsg-here",
            "palo_alto_ngfw_url": "https://x.x.x.x/api/",
            "palo_alto_password": "password-goes-here",
            "palo_alto_username": "service-account-name",
            "palo_api_token": "xxxxxxxxxxxxxxxxxxxxxx",
        }
        os.makedirs(os.path.dirname(self.config_file_path), exist_ok=True)
        with open(self.config_file_path, 'w') as config_file:
            yaml.dump(default_config, config_file, default_flow_style=False)
        logging.error(f"Config file created at {self.config_file_path}. Please update it with your environment details.")
        sys.exit(1)

    def check_for_default_settings(self):
        with open(self.config_file_path, 'r') as config_file:
            current_config = yaml.safe_load(config_file)
            default_indicators = ["enter-username", "xxxxxxxxxxxxxxxxxxxxxx", "enter-unique-tsg-here"]
            if any(indicator in str(current_config.values()) for indicator in default_indicators):
                logging.error(f"Default settings detected in {self.config_file_path}. Please update the file with your environment details.")
                sys.exit(1)
