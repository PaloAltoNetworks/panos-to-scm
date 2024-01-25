import requests
import yaml
import os
import urllib3
import logging
import xml.etree.ElementTree as ET
from requests.exceptions import SSLError

class PaloToken:
    def __init__(self, config_path='~/.panapi/config.yml'):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.config_path = os.path.expanduser(config_path)
        self.load_config()

    def load_config(self):
        with open(self.config_path, 'r') as file:
            self.config = yaml.safe_load(file)
            self.ngfw_url = self.config['palo_alto_ngfw_url']
            self.username = self.config['palo_alto_username']
            self.password = self.config['palo_alto_password']
            self.token = self.config.get('palo_api_token')

    def save_config(self):
        with open(self.config_path, 'w') as file:
            yaml.dump(self.config, file)
            logging.info("Token saved to config file.")

    def retrieve_token(self):
        if not self.token:
            logging.info("No existing token found for PANOS. Fetching a new API token...")
            payload = {'type': 'keygen', 'user': self.username, 'password': self.password}
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            try:
                response = self.make_request(headers, payload)
            except SSLError as e:
                user_input = input(f"Untrusted certificate from {self.ngfw_url} - continue? (yes/no): ").strip().lower()
                if user_input == 'yes':
                    response = self.make_request(headers, payload, verify=False)
                else:
                    raise e

            if response.status_code == 200:
                root = ET.fromstring(response.content)
                self.token = root.find('.//key').text
                self.config['palo_api_token'] = self.token
                self.save_config()
            else:
                raise Exception("Failed to retrieve token")
        else:
            logging.info("Using existing PANOS API token from config file.")
        return self.token

    def make_request(self, headers, payload, verify=True):
        return requests.post(self.ngfw_url + "?type=keygen", headers=headers, data=payload, verify=verify)
