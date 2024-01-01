#post_utils.py

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

import requests
import os
import time
import json
import logging
from log_module.scm_logging import setup_logging
setup_logging()
from api.token_utils import obtain_api_token, token_is_expired, refresh_token_if_needed
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Global lock for token refresh
token_refresh_lock = Lock()

def create_object(url, headers, item_data, retries=1, delay=5, client_id=None, client_secret=None, tsg_id=None):
    global token_refresh_lock
    with token_refresh_lock:
        access_token, headers["Authorization"] = refresh_token_if_needed(client_id, client_secret, tsg_id)

    for attempt in range(retries + 1):
        try:
            response = requests.post(url, headers=headers, json=item_data, timeout=10)
            if response.status_code == 201:
                return ('This object created', item_data['name'])
            else:
                error_response = response.json()
                if response.status_code == 400:
                    if "object already exists" in str(error_response).lower():
                        logging.info(f"Object already exists for '{item_data.get('name', '')}'")
                        return ('This object exists', item_data['name'])
                    if "is not a valid reference" in str(error_response).lower():
                        logging.warning(f"Invalid reference in object '{item_data.get('name', '')}' -- we do re-attempt, verify this went through properly'")
                        time.sleep(delay)
                        continue
                    logging.error(f"API Error for '{item_data.get('name', '')}': {error_response}, Status Code: {response.status_code}")
                else:
                    logging.error(f"API Error for '{item_data.get('name', '')}': {error_response}, Status Code: {response.status_code}")
                return ('error creating object', item_data['name'], "Error: Object creation failed")

        except Exception as e:
            logging.error(f"Exception occurred for '{item_data.get('name', '')}': {str(e)}")
            return ('error creating object', item_data['name'], "Exception occurred")

    return ('error creating object', item_data['name'], "Failed after retries")

def create_objects(scope, start_index, object_type, data, client_id, client_secret, tsg_id, max_workers, object_name_field='name', extra_query_params=''):
    url = f"https://api.sase.paloaltonetworks.com/sse/config/v1/{object_type}{extra_query_params}type=container&folder={scope}"
    headers = {
        "Content-Type": "application/json"
    }

    with token_refresh_lock:
        access_token, headers["Authorization"] = refresh_token_if_needed(client_id, client_secret, tsg_id)

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(create_object, url, headers, item_data, retries=2, delay=10, client_id=client_id, client_secret=client_secret, tsg_id=tsg_id) for item_data in data[start_index:]]

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print(result)
            logging.info(result)

    return results
