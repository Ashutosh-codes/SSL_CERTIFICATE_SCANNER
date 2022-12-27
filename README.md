# SSL_CERTIFICATE_SCANNER
This script can be used to find all the certificate details of an ssl certificate like issued on, expiry date, days left, domain issued to, state, country etc…, certificate Tls or ssl version, certifczte algorithm used,etc.
With the help of this script, we can automate the testssl.sh script to get the supported ciphers list and to check the vulnerabilities.
To run the command, you need to ensure that your python version is at least 3. So, if your python version is less than 3, please upgrade it
After this, to install pyopenssl, type:
'''
pip install pyopenssl
'''
Then we are ready to run our python script. 
To run the script, type:
'''
python ssl_certificate_scanner.py <host names separated by space>
'''
for example, to run the script on github.com and google.com type:
'''
python ssl_certificate_scanner.py github.com google.com
'''
