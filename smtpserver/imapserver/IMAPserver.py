import base64
import imaplib
import json
import logging
import os
import re
import socket
import ssl
import threading
# Default key to verify integrity of emails modified by the proxy
from imapserver.helper import process

DEFAULT_KEY = 'secret-proxy'

# Default maximum number of client supported by the proxy
MAX_CLIENT = 100

# Default ports
IMAP_PORT, IMAP_SSL_PORT = 143, 993
CRLF = b'\r\n'

# Tagged request from the client
Tagged_Request = re.compile(r'(?P<tag>[A-Z0-9]+)'
                            r'(\s(UID))?'
                            r'\s(?P<command>[A-Z]*)'
                            r'(\s(?P<flags>.*))?', flags=re.IGNORECASE)
# Tagged response from the server
Tagged_Response = re.compile(r'\A(?P<tag>[A-Z0-9]+)'
                             r'\s(OK)'
                             r'(\s\[(?P<flags>.*)\])?'
                             r'\s(?P<command>[A-Z]*)', flags=re.IGNORECASE)

# Capabilities of the proxy
CAPABILITIES = (
    'IMAP4',
    'IMAP4rev1',
    'AUTH=PLAIN',
    'UIDPLUS',
    'MOVE',
    'ID',
    'UNSELECT',
    'CHILDREN',
    'NAMESPACE'
)

# Authorized domain addresses with their corresponding host
HOSTS = {
    'outlook': 'outlook.office365.com',
    'gmail': 'imap.gmail.com',
    'yandex': 'imap.yandex.ru',
    'mail': 'imap.mail.ru'
}

# Intercepted commands
COMMANDS = (
    'authenticate',  # +
    'capability',  # +
    'login',
    'logout',
    'select',
    'move',
    'fetch',
    # 'noop', типа я жив клиент дай инфу
    # 'examine',
    # 'create',
    # 'delete',
    # 'rename',
    # 'subscribe',
    # 'unsubscribe',
    # 'list',
    # 'lsub',
    # 'status',
    # 'append',
    # 'check',
    # 'close',
    # 'expunge',
    # 'search',
    # 'store',
    # 'copy',
    # 'uid',
)


class IMAP_Proxy:
    r""" Implementation of the proxy.
    Instantiate with: IMAP_Proxy([port[, host[, certfile[, key[, max_client[, verbose[, ipv6]]]]]]])
            port - port number (default: None. Standard IMAP4 / IMAP4 SSL port will be selected);
            host - host's name (default: localhost);
            certfile - PEM formatted certificate chain file (default: None);
                Note: if certfile is provided, the connection will be secured over
                SSL/TLS. Otherwise, it won't be secured.
            key - Key used to verify the integrity of emails append by the proxy (default: 'secret-proxy')
            max_client - Maximum number of client supported by the proxy (default: global variable MAX_CLIENT);
            verbose - Display the IMAP payload (default: False)
            ipv6 - Should be enabled if the ip of the proxy is IPv6 (default: False)

    The proxy listens on the given host and port and creates an object IMAP4_Client (or IMAP4_Client_SSL for
    secured connections) for each new client. These socket connections are asynchronous and non-blocking.
    """

    def __init__(self, port=None, host='', certfile=None, keyfile=None, key=DEFAULT_KEY, max_client=MAX_CLIENT, verbose=False,
                 ipv6=False):
        self.verbose = verbose
        self.certfile = certfile
        self.keyfile = keyfile
        self.key = key
        self.logger = logging.getLogger("imapServer")

        if not port:  # Set default port
            port = IMAP_SSL_PORT if certfile else IMAP_PORT

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
                    ssock = ssl.wrap_socket(ssock, certfile=self.certfile, keyfile=self.keyfile, server_side=True)

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
    r""" Implementation of a connection with a client.
    Instantiate with: Connection([ssock[, verbose]])
            socket - Socket (with or without SSL/TLS) with the client
            verbose - Display the IMAP payload (default: False)

    Listens on the socket commands from the client.
    """

    def __init__(self, socket, key, verbose=False):
        self.verbose = verbose
        self.key = key
        self.conn_client = socket
        self.conn_server = None
        self.logger = logging.getLogger("imapServer")

        try:
            self.send_to_client('* OK IMAP4rev1 Service Ready.')  # Server greeting
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
                print(request)

                match = Tagged_Request.match(request)  # todo understand for what
                if not match:
                    if request != b'':
                        # Not a correct request
                        self.send_to_client(self.error('Incorrect request'))
                        self.logger.error(self.error('Incorrect request'))
                        raise ValueError('Error while listening the client: '
                                         + str(request) + ' contains no tag and/or no command')  # todo logging

                self.client_tag = match.group('tag')
                self.client_command = match.group('command').lower()
                self.client_flags = match.group('flags')
                self.request = request

                if self.client_command in COMMANDS:
                    # Command supported by the proxy
                    getattr(self, self.client_command)()
                else:
                    # Command unsupported -> directly transmit to the server
                    self.transmit()

    def transmit(self):
        """ Replace client tag by the server tag, transmit it to the server and listen to the server """
        server_tag = self.conn_server._new_tag().decode()
        self.send_to_server(self.request.replace(self.client_tag, server_tag, 1))
        self.listen_server(server_tag)

    def listen_server(self, server_tag):
        """ Continuously listen the server until a command completion response
        with the corresponding server_tag is received"""

        while True:

            response = self.recv_from_server()
            response_match = Tagged_Response.match(response)

            ##   Command completion response
            if response_match:
                server_response_tag = response_match.group('tag')
                if server_tag == server_response_tag:
                    # Verify the command completion corresponds to the client command
                    self.send_to_client(response.replace(server_response_tag, self.client_tag, 1))
                    return

                    ##   Untagged or continuation response or data messages
            self.send_to_client(response)

            if response.startswith('+') and self.client_command.upper() != 'FETCH':
                ##   Continuation response
                client_sequence = self.recv_from_client()
                while client_sequence != '' and not client_sequence.endswith('\r\n'):
                    self.send_to_server(client_sequence)
                    client_sequence = self.recv_from_client()
                self.send_to_server(client_sequence)

    def connect_server(self, username, password):
        """ Connect to the real server of the client for its credentials """

        self.username = self.remove_quotation_marks(username)
        self.password = self.remove_quotation_marks(password)

        domains = self.username.split('@')[1].split('.')[:-1]  # Remove before '@' and remove '.com' / '.be' / ...
        domain = ' '.join(str(d) for d in domains)

        try:
            hostname = HOSTS[domain]
        except KeyError:
            self.send_to_client(self.error('Unknown hostname'))
            self.logger.error('Error while connecting to the server: '
                             + 'Invalid domain name ' + domain)
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid domain name ' + domain)

        print("Trying to connect ", username)
        self.logger.info("Trying to connect ", username)
        self.conn_server = imaplib.IMAP4_SSL(hostname)

        try:
            self.conn_server.login(self.username, password)
        except imaplib.IMAP4.error:
            self.send_to_client(self.failure())
            self.logger.error('Error while connecting to the server: '
                             + 'Invalid credentials: ' + username)
            raise ValueError('Error while connecting to the server: '
                             + 'Invalid credentials: ' + username + " / " + password)

        self.send_to_client(self.success())

    #       Mandatory supported IMAP commands

    def capability(self):
        """ Send capabilites of the proxy """
        self.send_to_client('* CAPABILITY ' + ' '.join(cap for cap in CAPABILITIES))  # + ' +'
        self.send_to_client(self.success())

    def authenticate(self):
        """ Authenticate the client and call the given auth mechanism """
        auth_type = self.client_flags.split(' ')[0].lower()
        getattr(self, self.client_command + "_" + auth_type)()

    def authenticate_plain(self):  # todo understand
        """ Get the username and password using plain mechanism and
        connect to the server """
        self.send_to_client('+')
        request = self.recv_from_client()
        (empty, busername, bpassword) = base64.b64decode(request).split(b'\x00')
        username = busername.decode()
        password = bpassword.decode()
        with open(os.getcwd() + '\\imapserver\\access.json') as file:
            data = file.read()
            for user in json.loads(data)['emails']:
                if user == username:
                    access = True
                    break
        if not access:
            self.send_to_client(self.failure())
            return
        self.connect_server(username, password)

    def login(self):
        """ Login and connect to the server """
        (username, password) = self.client_flags.split(' ')
        self.connect_server(username, password)

    def logout(self):
        """ Logout and stop listening the client """
        self.listen_client = False
        self.send_to_client('* BYE IMAP 4.1 Server logging out')
        self.send_to_client(self.client_tag + ' OK LOGOUT completed')

    def select(self):
        """ Select a mailbox """
        self.set_current_folder(self.client_flags)
        self.transmit()

    #       CIRCL modules

    def change_UID(self):
        regex_UID = re.compile('(?<=UID fetch )[0-9]*(?= \()')
        uid = regex_UID.search(self.request)
        if uid:
            uid = uid.group()
            neww = str(int(uid) + 1)
            self.request = re.sub(regex_UID, neww, self.request)

    def change_UIDs(self, num):
        regex_UID1 = re.compile('(?<=UID fetch )[0-9]*(?=[:,])')
        uid1 = regex_UID1.search(self.request)
        if uid1:
            uid1 = uid1.group()
            neww1 = str(int(uid1) + 1)
            self.request = re.sub(regex_UID1, neww1, self.request)
        regex_UID2 = re.compile('(?<=:)[0-9]*(?= \()')
        uid2 = regex_UID2.search(self.request)
        if uid2:
            uid2 = uid2.group()
            neww2 = str(int(uid2) + num + 1)
            self.request = re.sub(regex_UID2, neww2, self.request)

    def fetch(self):
        """ Fetch an email """
        process(self)
        self.transmit()

    def move(self):
        """ Move an email to another mailbox """
        self.transmit()
    #       Command completion

    def success(self):
        """ Success command completing response """
        return self.client_tag + ' OK ' + self.client_command + ' completed'

    def failure(self):
        """ Failure command completing response """
        return self.client_tag + ' NO ' + self.client_command + ' failed.'

    def error(self, msg):
        """ Error command completing response """
        return ' BAD ' + msg.encode('cp850').decode('cp1251')

    #       Sending and receiving methods

    def send_to_client(self, str_data):
        """ Send String data (without CRLF) to the client """
        #print(str_data)
        self.logger.info(str_data)
        b_data = str_data.encode('utf-8', 'replace') + CRLF  # todo check
        self.conn_client.send(b_data)

        if self.verbose:
            print("[<--]: ", b_data)

    def recv_from_client(self):
        """ Return the last String request from the client without CRLF """

        b_request = self.conn_client.recv(4096)
        str_request = b_request.decode('utf-8', 'replace')[:-2]  # decode and remove CRLF

        if self.verbose:
            print("[-->]: ", b_request)

        return str_request

    def send_to_server(self, str_data):
        """ Send String data (without CRLF) to the server """

        b_data = str_data.encode('utf-8', 'replace') + CRLF
        self.conn_server.send(b_data)

        if self.verbose:
            print("  [-->]: ", b_data)

    def recv_from_server(self):
        """ Return the last String response from the server without CRLF """

        b_response = self.conn_server._get_line()
        str_response = b_response.decode('utf-8', 'replace')
        if self.verbose:
            print("  [<--]: ", b_response)

        return str_response

    #       Helpers

    def set_current_folder(self, folder):
        """ Set the current folder of the client """
        self.current_folder = self.remove_quotation_marks(folder)

    def remove_quotation_marks(self, text):
        """ Remove quotation marks from a String """
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        return text

IMAP_Proxy(port=143)
