import requests
import urllib3
import xml.etree.ElementTree as ET

class PaloConfigManager:
    def __init__(self, token, base_url):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.token = token
        self.base_url = base_url

    def get_running_config(self):
        headers = {'X-PAN-KEY': self.token}
        payload = {'type': 'config', 'action': 'show', 'xpath': '/config/'}
        response = requests.get(self.base_url, headers=headers, params=payload, verify=False)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            config_element = root.find('.//config')
            if config_element is not None:
                return ET.tostring(config_element, encoding='unicode')
            else:
                raise Exception("No config element found in the response")
        else:
            raise Exception("Failed to retrieve running configuration")
