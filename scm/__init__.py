# /project/scm/__init__.py
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
import logging
import time
import json
from urllib.parse import urlencode

class PanApiHandler:
    BASE_URL = "https://api.sase.paloaltonetworks.com"
    # BASE_URL = "https://api.strata.paloaltonetworks.com"

    def __init__(self, session):
        self.session = session

    def ensure_valid_token(self):
        """ Ensure the session token is valid. """
        self.session.ensure_valid_token()

from urllib.parse import urlencode, parse_qsl

class PanApiHandler:
    BASE_URL = "https://api.sase.paloaltonetworks.com"

    def __init__(self, session):
        self.session = session
        self.logger = logging.getLogger(__name__)

    def ensure_valid_token(self):
        """ Ensure the session token is valid. """
        self.session.ensure_valid_token()

    def get(self, endpoint, params=None, retries=1, delay=0.5):
        """ Retrieve objects or a specific object from the API using GET method. """
        self.ensure_valid_token()

        url = f"{self.BASE_URL}{endpoint}"
        
        # Handle different types of params input
        if params is None:
            params = {}
        elif isinstance(params, str):
            # If params is a string, parse it into a dictionary
            params = dict(parse_qsl(params.lstrip('?')))
        elif not isinstance(params, dict):
            self.logger.error(f"Invalid params type: {type(params)}. Expected dict or string.")
            return None

        if params:
            query_string = urlencode(params)
            full_url = f"{url}{query_string}"
        else:
            full_url = url

        self.logger.info(f'Fetching items: {full_url}')

        for attempt in range(retries + 1):
            try:
                response = self.session.get(url, params=params, timeout=20)
                if response.status_code == 200:
                    return response.json().get('data')
                else:
                    self.logger.error(f"API Error: {response.json()}, Status Code: {response.status_code}")
                    if attempt < retries:
                        time.sleep(delay)
            except Exception as e:
                self.logger.error(f"Exception: {str(e)}")
                if attempt < retries:
                    time.sleep(delay)

        return None

    def post(self, endpoint, item_data, retries=2, delay=0.5):
        """ Create or update an object via the API. """
        url = f"{self.BASE_URL}{endpoint}"
        for attempt in range(retries + 1):
            try:
                self.ensure_valid_token()
                response = self.session.post(url, json=item_data, timeout=20)
                if response.status_code in [200, 201]:
                    # Object created or updated successfully
                    return {'status': 'success', 'message': 'Object processed', 'name': item_data.get('name')}
                else:
                    # Handle API error responses
                    error_response = response.json()
                    if response.status_code == 400 and "object already exists" in str(error_response).lower():
                        logging.info(f"Object already exists for '{item_data.get('name', '')}'")
                        return {'status': 'exists', 'name': item_data.get('name'), 'response': error_response}
                    elif attempt < retries:
                        logging.warning(f"Retrying due to error for '{item_data.get('name', '')}': {response.text}")
                        time.sleep(delay)
                        continue
                    else:
                        logging.error(f"API Error for '{item_data.get('name', '')}': Response: {response.text}, Status Code: {response.status_code}")
                        return {'status': 'error', 'message': 'Error: Object creation failed', 'name': item_data.get('name'), 'response': error_response}
            except Exception as e:
                logging.error(f"Exception occurred for '{item_data.get('name', '')}': {str(e)}")
                if attempt < retries:
                    time.sleep(delay)
                else:
                    return {'status': 'exception', 'message': f"Exception: {str(e)}", 'name': item_data.get('name')}

        return {'status': 'failed', 'message': 'Failed after retries', 'name': item_data.get('name')}

    def put(self, endpoint, item_data, retries=2, delay=0.5):
        """ Update an object via the API. """
        url = f"{self.BASE_URL}{endpoint}"
        for attempt in range(retries + 1):
            try:
                self.ensure_valid_token()
                response = self.session.put(url, json=item_data, timeout=20)
                if response.status_code in [200, 204]:
                    return {'status': 'success', 'message': 'Object updated', 'name': item_data.get('name')}
                else:
                    error_response = response.json()
                    logging.error(f"API Error for '{item_data.get('name', '')}': {error_response}, Status Code: {response.status_code}")
                    if attempt < retries:
                        time.sleep(delay)
                    else:
                        return {'status': 'error', 'message': 'Error: Object update failed', 'name': item_data.get('name'), 'response': error_response}
            except Exception as e:
                logging.error(f"Exception occurred for '{item_data.get('name', '')}': {str(e)}")
                if attempt < retries:
                    time.sleep(delay)
                else:
                    return {'status': 'exception', 'message': f"Exception: {str(e)}", 'name': item_data.get('name')}

        return {'status': 'failed', 'message': 'Failed after retries', 'name': item_data.get('name')}

    def delete_object(self, endpoint, retries=1, delay=0.5):
        """ Delete an object via the API. """
        # Similar logic to get_object, but using session.delete
