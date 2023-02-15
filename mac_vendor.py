import requests

def get_mac_vendor(mac_adress):
    img_resp = requests.get('https://api.macvendors.com/'+mac_adress)
    answer=img_resp.content.decode()
    if 'errors' in answer:
        return ''
    return answer