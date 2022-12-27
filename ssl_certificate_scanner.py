import socket
import sys
import os
import json
from argparse import ArgumentParser
from ssl import PROTOCOL_TLSv1
from datetime import datetime
from OpenSSL import SSL

def convert_to_json(dict_obj):
    json_formatted_str = json.dumps(dict_obj, indent=2)
    print(json_formatted_str)

def get_cert_sans(x509cert):
    san = ''
    ext_count = x509cert.get_extension_count()
    sans = []
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
            sans.append(san)
        
    return sans

def get_cert(host, port):
    """ Returns the certificate of host """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = SSL.Context(PROTOCOL_TLSv1)
    sock.connect((host, int(port)))
    conn = SSL.Connection(context, sock)
    conn.set_tlsext_host_name(host.encode())
    conn.set_connect_state()
    conn.do_handshake()
    cert = conn.get_peer_certificate()
    sock.close()

    return cert

def filter_hostname(host):
    """Remove unused characters and split by address and port."""
    host = host.replace('http://', '').replace('https://', '').replace('/', '')
    port = 443
    if ':' in host:
        host, port = host.split(':')

    # To remove the "www." part from the url so as to get all the SAN of the website
    if(host[0:3] == 'www'):
        host = host[4:]
    return host, port

def check_vulnerabilities_and_ciphers(host):
    """ This function checks for vulnerabilities """
    output = os.popen("testssl.sh/testssl.sh --sneaky -U -e --quiet --color 0 --fast " + host).read()
    print("Checking for vulerabilities and supported ciphers")
    print(output)

def get_cert_info(cert, host):
    """ Returns the info of the certificate """
    context = {}

    cert_subject = cert.get_subject()

    context['host'] = host
    context['issued_to'] = cert_subject.CN
    context['issued_o'] = cert_subject.O
    context['issuer_c'] = cert.get_issuer().countryName
    context['issuer_o'] = cert.get_issuer().organizationName
    context['issuer_ou'] = cert.get_issuer().organizationalUnitName
    context['issuer_cn'] = cert.get_issuer().commonName
    context['cert_sn'] = str(cert.get_serial_number())
    context['cert_sha1'] = cert.digest('sha1').decode()
    context['cert_alg'] = cert.get_signature_algorithm().decode()
    context['cert_ver'] = cert.get_version()
    context['cert_sans'] = get_cert_sans(cert)
    context['cert_exp'] = cert.has_expired()
    context['cert_valid'] = False if cert.has_expired() else True

    # Valid from
    valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
    context['valid_from'] = valid_from.strftime('%Y-%m-%d')

    # Valid till
    valid_till = datetime.strptime(cert.get_notAfter().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
    context['valid_till'] = valid_till.strftime('%Y-%m-%d')

    # Validity days
    context['validity_days'] = (valid_till - valid_from).days

    # Validity in days from now
    now = datetime.now()
    context['days_left'] = (valid_till - now).days

    # Valid days left
    context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'],
                                           '%Y-%m-%d') - datetime.now()).days
    
    convert_to_json(context)
    return context

def cert_details(host):
    """ Get all the details of the certificate """
    context = {}
    host, port = filter_hostname(host)
    print(host)
    cert = get_cert(host, port)
    get_cert_info(cert, host)
    check_vulnerabilities_and_ciphers(host)

parser = ArgumentParser(prog='ssl_certificate_scaner.py', add_help='False', 
                        description="""Collects useful information about given host's SSL certificates 
                        and check for vulenrabilities""")

parser.add_argument('hosts', nargs='+')
# parser = parser.parse_args(['google.com', 'github.com'])
# to parse the arguments
# To run the tool type python ssl_certificate_scanner.py <list of hosts>
# example ->  python ssl_certificate_scanner.py github.com google.com
args = parser.parse_args()

for host in args.hosts:
    cert_details(host)
# cert_details("https://www.google.com/")