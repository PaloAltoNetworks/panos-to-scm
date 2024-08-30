import requests
import xml.etree.ElementTree as ET
import logging
from requests.exceptions import SSLError

class PaloConfigManager:
    def __init__(self, token, base_url, ssl_untrusted=False):
        print("Using PaloConfigManager with ssl_untrusted parameter:", ssl_untrusted)
        self.token = token
        self.base_url = base_url
        self.ssl_untrusted = ssl_untrusted  # Correctly handle ssl_untrusted parameter

    def get_running_config(self):
        headers = {'X-PAN-KEY': self.token}
        payload = {'type': 'config', 'action': 'show', 'xpath': '/config/'}
        try:
            response = self.make_request(headers, payload, verify=self.ssl_untrusted)  # Properly use ssl_untrusted
        except SSLError as e:
            if self.ssl_untrusted:
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
        print(f"Making request with SSL verification set to {verify}")  # Debugging print statement
        return requests.get(self.base_url, headers=headers, params=payload, verify=verify)
