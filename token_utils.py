#token_utils.py

import requests
import json
import time
import os
import logging
from requests.exceptions import RequestException

# Global variable to store the token
token_data = None

def token_is_expired():
    global token_data
    if token_data:
        current_time = time.time()
        return current_time > token_data.get('expires_at', 0)
    return True  # No token data means it's expired or non-existent

def refresh_token_if_needed(client_id, client_secret, tsg_id):
    global token_data
    if token_is_expired():
        obtain_api_token(client_id, client_secret, tsg_id, force_refresh=True)
    return token_data.get("access_token"), f"Bearer {token_data.get('access_token')}"

def obtain_api_token(client_id, client_secret, tsg_id, force_refresh=False):
    global token_data

    # Check if token is cached and valid
    if not force_refresh and token_data:
        if time.time() < token_data.get("expires_at", 0):
            logging.info("Returning cached token")
            return token_data.get("access_token")

    logging.info("Fetching new Token because it's expired or force_refresh is set")
    print("Fetching new Token because it's expired or force_refresh is set")
    start_time = time.time()

    url = 'https://auth.apps.paloaltonetworks.com/oauth2/access_token'
    payload = {'grant_type': 'client_credentials', 'scope': f'tsg_id:{tsg_id}'}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    response = requests.post(url, data=payload, headers=headers, auth=(client_id, client_secret))

    if response.status_code == 200:
        data = response.json()
        token = data["access_token"]
        expires_in = data["expires_in"]
        elapsed_time = time.time() - start_time
        logging.info(f"New token fetched successfully in {elapsed_time:.2f} seconds")

        # Update global token_data
        token_data = {
            "access_token": token,
            "expires_at": time.time() + expires_in - 180  # Subtract 180 seconds to account for potential delays
        }

        return token
    else:
        error_msg = f"Error fetching token: {response.status_code} {response.reason}"
        logging.error(error_msg)
        raise RequestException(error_msg)
