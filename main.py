from urllib.parse import urlparse
import requests
import socket
import http.client
import subprocess
import socket

def get_ip(host):
    domain = urlparse(host).netloc
    ip = socket.gethostbyname(domain)
    return ip

def check_ssl(host):
    try:
        response = requests.get(host, timeout=5)
        if response.url.startswith('https://'):
            return True
    except (requests.exceptions.SSLError, requests.exceptions.RequestException):
        pass
    return False

def check_cloud(host):
    parsed_url = urlparse(host)
    try:
        connection = http.client.HTTPSConnection(parsed_url.netloc, timeout=5) if parsed_url.scheme == 'https' else http.client.HTTPConnection(parsed_url.netloc, timeout=5)
        connection.request("HEAD", parsed_url.path)

        res = connection.getresponse()
        srv = res.getheader('Server')

    except (http.client.HTTPException, OSError):
        return None, None

    finally:
        connection.close()

    return srv


def check_waf(host):
    result = subprocess.run(['wafw00f', host], capture_output=True, text=True)
    if "No WAF detected" in result.stdout:
        return False
    else:
        return True
    
def get_loc(host):
    response = requests.get(f'https://ipapi.co/{host}/json/').json()
    location_data = {
        "city": response.get("city"),
        "region": response.get("region"),
        "country": response.get("country_name")
    }
    return location_data
    
with open('hosts.txt', 'r') as file:
    sites = file.read().splitlines()

for site in sites[:10]:
    ip = get_ip(site)
    ssl = check_ssl(site)
    srv = check_cloud(site)
    waf = check_waf(site)
    loc = get_loc(ip)
    print("WEBSITE ANALISADO: ", site)
    print("IP: ", ip)
    print("CERTIFICADO SSL: ", ssl)
    print("SERVIDOR: ", srv)
    print("WAF: ", waf)
    print("LOCALIZAÇÃO", loc['country'])
    print()