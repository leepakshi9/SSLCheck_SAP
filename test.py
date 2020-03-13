from datetime import datetime
from OpenSSL import crypto as c
import os
from socket import socket
from OpenSSL import SSL
from argparse import ArgumentParser

def getWarning(expiryDate):
    '''
    This function reads the expiry date and checks the duration of validity of the certificate.
    Prints CRITICAL in red if certificate expires in less than 15 days
    Prints WARNING in yellow if certificate expires in less than 30 days
    Prints INFO in green if certificate doesn't expire in the next 30 days
    :param expiryDate: str
    :return: None
    '''
    now=datetime.strptime(datetime.now().strftime("%d/%m/%Y"),"%d/%m/%Y")
    expiryDate=datetime.strptime(expiryDate,"%d/%m/%Y")
    print("---->",end=' ')
    if expiryDate>now:
        duration=expiryDate-now
        expiry=duration.days
        if expiry<=15:
            print ('\033[31m'+"CRITICAL"+'\033[39m')
        elif expiry <=30:
            print ('\033[33m'+"WARNING"+'\033[39m')
        else:
            print ('\033[32m'+"INFO"+'\033[39m')

        print(str(expiry)+" days left")
    else:
        print("Expired")


def formatX509Name(nameList):
    '''
    Takes in the list of tuples and formats using mappings dictionary
    :param nameList: list of tuples of components of SSL certificate
    :return: formatted string
    '''
    """
    From crypto.py https://github.com/pyca/pyopenssl/blob/8cd3b17ec79ec2049eb9d8d6d162b417012144a2/src/OpenSSL/crypto.py#L508
    An X.509 Distinguished Name.
    :ivar countryName: The country of the entity.
    :ivar C: Alias for  :py:attr:`countryName`.
    :ivar stateOrProvinceName: The state or province of the entity.
    :ivar ST: Alias for :py:attr:`stateOrProvinceName`.
    :ivar localityName: The locality of the entity.
    :ivar L: Alias for :py:attr:`localityName`.
    :ivar organizationName: The organization name of the entity.
    :ivar O: Alias for :py:attr:`organizationName`.
    :ivar organizationalUnitName: The organizational unit of the entity.
    :ivar OU: Alias for :py:attr:`organizationalUnitName`
    :ivar commonName: The common name of the entity.
    :ivar CN: Alias for :py:attr:`commonName`.
    :ivar emailAddress: The e-mail address of the entity.
    """
    mappings = {'C':"Country Name",'ST':"State Or Province Name",'L':"Locality Name",'O':"Organization Name",'OU':"Organizational Unit Name",'CN':"Common Name"}
    resultString = ''
    for i in nameList:
        try:
            resultString += mappings[i[0].decode()]+' : '+i[1].decode()+'\n'
        except:
            resultString += i[0].decode()+' : '+i[1].decode()+'\n'
    return resultString

def formattedOutput(certificate,info):
    '''
    Prints the validity of expiry and warning
    :param cert: SSL certificate
    :param info: flag to print information
    :return: None
    '''
    if info:
        certname = certificate.get_subject()
        print("Issued Domain Name : " + certname.commonName)
        print(formatX509Name(certificate.get_issuer().get_components()))
    expiryDate = datetime.strptime(certificate.get_notAfter().decode(), "%Y%m%d%H%M%SZ").strftime("%d/%m/%Y")
    print("Expiry Date : ", expiryDate)
    getWarning(expiryDate)


def localSSLCheck(crtfile,info):
    '''
    Reads local ssl file
    :param crtfile: certificate file
    :param info: flag to display detailed information
    :return: None
    '''
    try:
        certificate = c.load_certificate(c.FILETYPE_PEM, open(crtfile, 'r').read())
        print("---------------------------------------------------------------------")
        formattedOutput(certificate, info)
    except Exception as e:
        print("Error opening file")
        print(Exception)


def remoteSSLCheck(hostname, port, info):
    '''
    Connects and reads ssl certificate from given hostname and port
    :param hostname: hostname of remote server
    :param port: port number of remote server
    :param info: flag to display detailed information
    :return: None
    '''
    try:
        sock = socket()

        sock.connect((hostname, port))
        context = SSL.Context(SSL.SSLv23_METHOD)

        SSLsocket = SSL.Connection(context, sock)
        SSLsocket.set_connect_state()
        # handshake is handled automatically by read/write.
        SSLsocket.set_tlsext_host_name(hostname.encode())
        SSLsocket.do_handshake()

        certificate = SSLsocket.get_peer_certificate()
        formattedOutput(certificate, info)
        SSLsocket.close()
        sock.close()
    except SSL.Error as e:
        print(e)

def get_args():
    '''
    Parses input arguments and calls the appropriate function
    :return: None
    '''
    parser = ArgumentParser(prog='test.py', add_help=False)

    parser.add_argument('-L', '--local', dest='local', default=False, action='store_true',
                        help='Flag to enable local server check')
    parser.add_argument('-f', '--crtFile', dest='crtFile', default=False,
                        help='Full path of SSL certificate file on local server')
    parser.add_argument('-R', '--remote', dest='remote', default=False, action='store_true',
                        help='Flag to enable remote server check')
    parser.add_argument('-h', '--host', dest='hostname', default=False,
                        help='Hostname of remote server')
    parser.add_argument('-p', '--port', dest='port', default=False,
                        help='Port number of remote server')
    parser.add_argument('-I', '--info', dest='info', action='store_true',
                        help='Displays extra information about SSL certificate')

    args = parser.parse_args()
    INFO = False
    if args.info:
        INFO = True

    try:
        if args.remote:
            remoteSSLCheck(hostname=args.hostname, port=int(args.port), info=INFO)
        elif args.local:
            localSSLCheck(crtfile=args.crtFile,info=INFO)
        else:
            remoteSSLCheck(hostname='localhost', port=443, info=INFO)
    except Exception as e:
        print(e)

if __name__ == '__main__':
    get_args()