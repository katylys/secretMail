"""
    Implementation of the proxy
"""
import base64
import json
import logging
import os
import re
import smtplib
import socket
import ssl
import threading

import requests
from cryptography.fernet import Fernet

DEFAULT_KEY = 'secret-proxy'

# Default maximum number of client supported by the proxy
MAX_CLIENT = 100

# Default ports
SMTP_PORT, SMTP_SSL_PORT = 587, 465
CRLF = b'\r\n'
UID = 0  # type: int

# Tagged request from the client
Tagged_Request = re.compile(r'\s*(?P<command>((AUTH PLAIN)|QUIT|EHLO|(MAIL FROM)|(RCPT TO)|DATA|))'
                            r'(\s*(?P<flags>.*))?', flags=re.IGNORECASE)
# Tagged response from the server
Tagged_Response = re.compile(r'\A(?P<tag>[A-Z0-9]+)'
                             r'\s(OK)'
                             r'(\s\[(?P<flags>.*)\])*'
                             r'\s(?P<command>[A-Z]*)', flags=re.IGNORECASE)

ReText = re.compile(r'(?<=\r\n\r\n)(.*\n)*(?=\r\n.)', flags=re.IGNORECASE)

HOSTS = {
    'outlook': {'host': 'smtp-mail.outlook.com', 'ssl': 'False', 'port': '587'},
    'gmail': {'host': 'smtp.gmail.com', 'ssl': 'True', 'port': '465'},
    'yandex': {'host': 'smtp.yandex.ru', 'ssl': 'True', 'port': '0'},
    'mail': {'host': 'smtp.mail.ru',  'ssl': 'True', 'port': '465'},
}

# Intercepted commands
COMMANDS = (
    'auth_plain',
    'mail_from',
    'rcpt_to',
    'data',
    'ehlo',
    'quit',
)

class SMTP_Proxy:

    def __init__(self, port=None, host='', certfile=None, keyfile=None, key=DEFAULT_KEY, max_client=MAX_CLIENT, verbose=False,
                 ipv6=False):
        self.verbose = verbose
        self.certfile = certfile
        self.keyfile = keyfile
        self.key = key
        self.logger = logging.getLogger("smtpServer")

        if not port:  # Set default port
            port = SMTP_SSL_PORT if certfile else SMTP_PORT

        if not max_client:
            max_client = MAX_CLIENT

        # IPv4 or IPv6
        addr_fam = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.sock = socket.socket(addr_fam, socket.SOCK_STREAM)

        self.sock.bind(('', port))
        self.sock.listen(max_client)
        self.listen()

    def listen(self):
        """ Wait and create a new Connection for each new connection with a client. """

        while True:
            try:
                ssock, addr = self.sock.accept()
                if self.certfile:  # Add SSL/TLS
                    ssock = ssl.wrap_socket(ssock, certfile=self.certfile, keyfile=self.keyfile, server_side=True, do_handshake_on_connect=False)

                # Connect the proxy with the client
                threading.Thread(target=self.new_connection, args=(ssock,)).start()
            except KeyboardInterrupt:
                break
            except ssl.SSLError as e:
                raise

        if self.sock:
            self.sock.close()

    def new_connection(self, ssock):
        Connection(ssock, self.key, self.verbose)


class Connection:

    def __init__(self, socket, key, verbose=False):
        self.verbose = verbose
        self.key = key
        self.conn_client = socket
        self.conn_server = None
        self.rcpt = []
        self.logger = logging.getLogger("smtpServer")

        try:
            self.send_to_client('220 SMTP ready')
            self.listen_client()
        except ssl.SSLError:
            pass
        except (BrokenPipeError, ConnectionResetError) as e:
            print('Connections closed        ' + str(e))  # todo logging
        except ValueError as e:
            print('[ERROR]', e)  # todo logging

        if self.conn_client:
            self.conn_client.close()

    #       Listen client/server and connect server

    def listen_client(self):
        """ Listen commands from the client """

        while self.listen_client:
            tmp = self.recv_from_client()
            help = tmp.split('\r\n')
            for request in help:  # In case of multiple requests
                self.logger.info(request)
                match = Tagged_Request.match(request)  # todo understand for what
                if not match:
                    if request != b'':
                        # Not a correct request
                        self.logger.error('Incorrect request')
                        self.send_to_client(self.error('Incorrect request'))
                        raise ValueError('Error while listening the client: '
                                         + str(request) + ' contains no tag and/or no command')  # todo logging

                self.client_command = '_'.join(match.group('command').lower().split(' '))
                self.client_flags = match.group('flags')
                self.request = request

                if self.client_command in COMMANDS:
                    # Command supported by the proxy
                    getattr(self, self.client_command)()
                else:
                    # Command unsupported -> directly transmit to the server
                    self.transmit()

    def data(self):
        self.send_to_client('354 Start mail input; end with <CRLF>.<CRLF>')
        string = self.recv_from_client()
        arr = string.split('\r\n\r\n')
        headers = arr.pop(0)
        text = '\r\n'.join(arr)
        for rcpt in self.rcpt:
            if rcpt != self.rcpt[0]:
                self.request = self.ehloRequest
                self.ehlo()
                self.client_flags = self.auth_plainFlags
                self.auth_plain()
                self.request = self.mail_fromRequest
                self.send_to_server(self.request)
                self.recv_from_server()
            self.send_to_server('RCPT TO:<' + rcpt + '>')
            self.recv_from_server()
            self.send_to_server('DATA')
            self.recv_from_server()
            response = requests.post("http://217.73.60.165:2680/makeKey", data={'userFrom': self.mailFrom, 'userTo': rcpt})
            jsonText = response.json()
            key = jsonText['key']
            uid = jsonText['uid']
            fernet = Fernet(key)
            forenc = text.split('\r\n.')[0]
            subject = re.findall(r'(?<=Subject: ).*(?=\r\n)', headers)
            if subject:
                subject = "Subject: " + subject[0] + "\n"
                headers = re.sub(r'(?<=Subject: )(.*(\r\n)*)*(?=.*)', "Secret subject", headers)
            else:
                subject = ""
            forenc = forenc + subject
            eeenc = fernet.encrypt(str(forenc).encode()).decode("utf-8")

            headers = re.sub(r'(?<=To: )(.*(\r\n)*)*(?=.*)', rcpt.split('@')[0] + ' <' + rcpt + '>', headers)
            exuid = re.findall(r'(?<=UID: ).*', headers)
            if not exuid:
                headers += '\r\nUID: ' + str(uid) + '\r\n'
                headers += 'SCM: encrypt\r\n'
            else:
                headers = re.sub(r'(?<=UID: ).*(?=\r\n)', str(uid), headers)
            all = headers + '\r\n' + eeenc + '\r\n.'
            self.send_to_server(all)
            if rcpt == self.rcpt[0]:
                self.recv_from_server()
                self.send_to_client('250 OK')

    def transmit(self):
        """ Replace client tag by the server tag, transmit it to the server and listen to the server """
        self.send_to_server(self.request)
        self.listen_server()

    def listen_server(self):
        """ Continuously listen the server until a command completion response
        with the corresponding server_tag is received"""

        while True:

            response = self.recv_from_server()
            if response[:3] == '354':
                self.send_to_client(response)
            else:
                self.send_to_client(response[:3] + ' OK')
            return

            self.send_to_client(response)

    def connect_server(self, username, password):
        """ Connect to the real server of the client for its credentials """

        self.username = self.remove_quotation_marks(username)
        self.password = self.remove_quotation_marks(password)

        domains = self.username.split('@')[1].split('.')[:-1]  # Remove before '@' and remove '.com' / '.be' / ...
        domain = ' '.join(str(d) for d in domains)

        try:
            hostname = HOSTS[domain]['host']
        except KeyError:
            self.logger.error('Error while connecting to the server: '
                             + 'Invalid domain name ' + domain)
            self.send_to_client(self.error('Unknown hostname'))
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid domain name ' + domain)

        print("Trying to connect ", username)
        if HOSTS[domain]['ssl'] == 'True':
            self.conn_server = smtplib.SMTP_SSL(hostname, int(HOSTS[domain]['port']))
        else:
            self.conn_server = smtplib.SMTP(hostname, int(HOSTS[domain]['port']))
            self.conn_server.starttls()

        self.conn_server.set_debuglevel(1)
        try:
            self.conn_server.login(self.username, password)
        except smtplib.SMTP.error:
            self.send_to_client(self.failure())
            self.logger.error('Error while connecting to the server: '
                             + 'Invalid credentials: ' + username)
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid credentials: ' + username)
        self.send_to_client(self.success())

    def auth(self):
        """ Authenticate the client and call the given auth mechanism """
        auth_type = self.client_flags.split(' ')[0].lower()
        getattr(self, self.client_command + "_" + auth_type)()

    def ehlo(self):
        self.ehloRequest = self.request
        self.send_to_client('250-SecretMail Hello')
        self.send_to_client('250 AUTH GSSAPI DIGEST-MD5 PLAIN')

    def quit(self):
        #self.listen_client = False
        self.send_to_client('221 SecretMail Service closing transmission channel')

    def auth_plain(self):  # todo understand
        """ Get the username and password using plain mechanism and
        connect to the server """
        self.auth_plainFlags = self.client_flags
        t = base64.b64decode(self.auth_plainFlags).split(b'\x00')
        (empty, busername, bpassword) = base64.b64decode(self.auth_plainFlags).split(b'\x00')
        access = False
        username = busername.decode()
        password = bpassword.decode()
        with open(os.getcwd() + '\\smtpserver\\access.json') as file:
            data = file.read()
            for user in json.loads(data)['emails']:
                if user == username:
                    access = True
                    break
        if not access:
            self.send_to_client(self.failure())
            return
        self.connect_server(username, password)

    def mail_from(self):
        self.mail_fromRequest = self.request
        self.mailFrom = self.client_flags[2:-1]
        self.transmit()

    def rcpt_to(self):
        rcpt = self.client_flags[2:-1]
        if rcpt not in self.rcpt and rcpt != self.mail_from:
            self.rcpt.append(rcpt)
        self.send_to_client('250 OK')


    def login(self):
        """ Login and connect to the server """
        (username, password) = self.client_flags.split(' ')
        self.connect_server(username, password)

    def success(self):
        """ Success command completing response """
        return '250 OK ' + self.client_command + ' completed'

    def failure(self):
        """ Failure command completing response """
        return '550 NO ' + self.client_command + ' failed.'

    def error(self, msg):
        """ Error command completing response """
        return ' BAD ' + msg.encode('cp850').decode('cp1251')

    #       Sending and receiving methods

    def send_to_client(self, str_data):
        """ Send String data (without CRLF) to the client """
        self.logger.info(str_data)
        print(str_data)
        b_data = str_data.encode('utf-8', 'replace') + CRLF  # todo check
        self.conn_client.send(b_data)

        if self.verbose:
            print("[<--]: ", b_data)

    def recv_from_client(self):
        """ Return the last String request from the client without CRLF """
        b_request = self.conn_client.recv(4000)
        b_request = b_request.decode('utf-8')
        y = b_request
        while not y.endswith('\r\n'):
            y = self.conn_client.recv(4000).decode('utf-8')
            b_request += y

        str_request = b_request[:-2]  # decode and remove CRLF

        if self.verbose:
            print("[-->]: ", b_request)

        return str_request

    def send_to_server(self, str_data):
        """ Send String data (without CRLF) to the server """

        b_data = str(str_data).encode('utf-8', 'replace') + CRLF
        self.conn_server.send(b_data)

        if self.verbose:
            print("  [-->]: ", b_data)

    def recv_from_server(self):
        """ Return the last String response from the server without CRLF """

        b_response = ''.join(str(self.conn_server.getreply()))
        str_response = b_response[1:-1].replace(',', ' ')
        if self.verbose:
            print("  [<--]: ", b_response)

        return str_response

    #       Helpers

    def remove_quotation_marks(self, text):
        """ Remove quotation marks from a String """
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        return text


SMTP_Proxy(port=25)
