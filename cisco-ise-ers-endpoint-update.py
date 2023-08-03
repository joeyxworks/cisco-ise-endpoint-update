import requests
import json
import os
import logging
import re
import argparse
import sys
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import RequestException, Timeout, TooManyRedirects, HTTPError
from json.decoder import JSONDecodeError


# Argument Parser
parser = argparse.ArgumentParser(description="A script for updating a new endpoint using Cisco ISE ERS API")

parser.add_argument("-m", "--mac", type=str, required=True, help="The MAC address of the endpoint")
parser.add_argument("-t", "--type", type=str, required=True, help="The type of the endpoint")
parser.add_argument("-d", "--description", type=str, required=False, help="The description of the endpoint")
# parser.add_argument("-i", "--ise_address", type=str, required=True, help="The address of the ISE server")

# Parse the arguments
args = parser.parse_args()

endpoint_types = {
    'endpoint_type_a':{
        'group':'Group_NAME_A',
        'id':'aaffbb40-8baf-22e6-126c-525401238521',
        },
    'endpoint_type_b':{
        'group':'Group_NAME_B',
        'id':'bbf5cac0-8a00-13e6-196c-512300b48521'
    },
}


# Disable warning for self-signed certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Variables
USERNAME = os.getenv('ISE_ERS_USER')
PASSWORD = os.getenv('ISE_ERS_PASSWD')

ise_address = '[ISE_ADDRESS]' # Change here
mac_address = args.mac
endpoint_description = args.description

def validate_endpoint_type(endpoint_type):
    # Group IDs are continuous strings with characters '-', '_', '0-9', 'a-z', 'A-Z'
    type_pattern = re.compile('^[_0-9a-zA-Z]+$')

    if type_pattern.match(endpoint_type):
        return True
    else:
        return False

def grab_endpoint_group(endpoint_type):
    if validate_endpoint_type(endpoint_type):
        return endpoint_types[endpoint_type]['id']
    else:
        logging.error("Invalid Endpoint type.")
        sys.exit(1)


def validate_mac_addr(mac_address):
    """
    Validate the provided MAC address

    Arguments:
    mac_address -- MAC address to be validated

    Returns:
    True if the MAC address is valid, False otherwise.
    """
    # MAC addresses are 6 groups of two hexadecimal digits, separated by hyphens (-) or colons (:)
    mac_pattern = re.compile('^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

    if mac_pattern.match(mac_address):
        return True
    else:
        return False

def get_endpoint_id(mac_address):
    url = f'https://{ise_address}:9060/ers/config/endpoint?filter=mac.EQ.{mac_address}'

    headers = {
    'ACCEPT': 'application/json',
    }

    response = send_request("GET", url, headers, None)
    data = response.json()

    if data['SearchResult']['total'] == 1:
        try:
            resources = data['SearchResult']['resources']
            for resource in resources:
                endpoint_id = resource['id']
                return endpoint_id
                
        except JSONDecodeError:
            logging.error("The MAC address is not valid, please submit your MAC address again.")
            # print("The MAC address is not valid, please submit your MAC address again.")
            sys.exit(1)
    else:
        logging.info("MAC address not found.")
        # print("MAC address not found.")
        # return None
        sys.exit(1)


def get_group_id(endpoint_group):
    url = f'https://{ise_address}:9060/ers/config/endpointgroup/name/{endpoint_group}'

    headers = {
    'ACCEPT': 'application/json',
    }

    response = send_request("GET", url, headers, None)

    try:
        group_id = response.json()['EndPointGroup']['id']
        return group_id

    except JSONDecodeError:
        logging.error("The endpoint group is not valid, please submit your group again.")
        sys.exit(1)

def send_request(method, url, headers, data):
    with requests.Session() as s:
        try:
            response = s.request(method, url, headers=headers, data=data, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
            response.raise_for_status()
            logging.info(response.text)
            return response
        except HTTPError as http_err:
            logging.error(f"HTTP error occurred while requesting {url}. Error is: {http_err}")
            sys.exit(1)
        except RequestException as req_err:
            logging.error(f"Error occurred while requesting {url}. Error is: {req_err}")
            sys.exit(1)

def update_new_endpoint(group_id, candidate_mac_address, candidate_description):
    headers = {
        'content-type': 'application/json',
        'accept': 'application/json'
    }

    data = {
        "ERSEndPoint" : {
            "name" : f"{candidate_mac_address}",
            "description" : f"{candidate_description}",
            "mac" : f"{candidate_mac_address}",
            "groupId" : f"{group_id}",
            "staticGroupAssignment" : True
        }}

    endpoint_id = get_endpoint_id(candidate_mac_address)
    # Use different API to update endpoints
    if endpoint_id:
        url = f'https://{ise_address}:9060/ers/config/endpoint/{endpoint_id}'
        send_request("PUT", url, headers, json.dumps(data))
        logging.info(f"{candidate_mac_address} successfully updated!")

    else:
        url = f'https://{ise_address}:9060/ers/config/endpoint'
        send_request("POST", url, headers, json.dumps(data))
        logging.info(f"{candidate_mac_address} successfully imported!")


def main():
    if not validate_mac_addr(mac_address):
        logging.error("Invalid MAC address.")
        sys.exit(1)

    else:
        description = args.description
        endpoint_group_id = grab_endpoint_group(args.type)
        update_new_endpoint(endpoint_group_id, mac_address, description)
        logging.info("Successfully updated.")       

if __name__ == '__main__':
    main()
