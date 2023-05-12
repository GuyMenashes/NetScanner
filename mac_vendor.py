# Importing necessary modules
import requests

def get_mac_vendor(mac_adress):
    '''
    Given a MAC address, uses the API from https://macvendors.com to retrieve the vendor name of the device that has that MAC address.

    Parameters:
        - mac_address (str): a MAC address in the format xx:xx:xx:xx:xx:xx

    Returns:
        - The vendor name of the device that has the given MAC address (str). If the API call fails, an empty string is returned.
    '''
    # Build the API URL with the given MAC address
    url = 'https://api.macvendors.com/' + mac_adress

    # Send a GET request to the API URL and store the response in img_resp
    img_resp = requests.get(url)

    # Decode the content of the response as a string
    answer = img_resp.content.decode()

    # If the response contains the word 'errors', the API call has failed, so return an empty string
    if 'errors' in answer:
        return ''

    # Otherwise, return the vendor name of the device that has the given MAC address
    return answer