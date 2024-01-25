import requests
import xml.etree.ElementTree as ET
import logging
from requests.exceptions import SSLError

class PaloConfigManager:
    def __init__(self, token, base_url):
        self.token = token
        self.base_url = base_url

    def get_running_config(self):
        headers = {'X-PAN-KEY': self.token}
        payload = {'type': 'config', 'action': 'show', 'xpath': '/config/'}
        try:
            response = self.make_request(headers, payload)
        except SSLError as e:
            user_input = input(f"Untrusted certificate from {self.base_url} - continue? (yes/no): ").strip().lower()
            if user_input == 'yes':
                response = self.make_request(headers, payload, verify=False)
            else:
                raise e

        if response.status_code == 200:
            root = ET.fromstring(response.content)
            config_element = root.find('.//config')
            if config_element is not None:
                logging.info(f'Successfully downloaded XML configuration from: {self.base_url}')
                return ET.tostring(config_element, encoding='unicode')
            else:
                raise Exception("No config element found in the response")
        else:
            raise Exception("Failed to retrieve running configuration")

    def make_request(self, headers, payload, verify=True):
        return requests.get(self.base_url, headers=headers, params=payload, verify=verify)
