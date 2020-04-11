"""
    Implementation of the PyCIRCLeanMail module.
    Sanitize emails before being fetched by the user.
"""
import email, re, imaplib, time, hashlib, hmac
import logging

import requests

from cryptography.fernet import Fernet

Fetch = re.compile(r'(?P<tag>[A-Z0-9]+)'
                   r'(\s(UID))?'
                   r'\s(FETCH)'
                   r'\s(?P<ids>[0-9:,]+)'
                   r'\s(?P<flags>.*)', flags=re.IGNORECASE)

# Message data used to get the entire mail
MSG_DATA = 'BODY.PEEK[]'

def parse_ids(str_ids):
    """ Convert string of ids to a list of ids
        str_ids - ids of format "1:6" or "1,3:5" or "1,4"
    If str_ids = "1:6", return (1,2,3,4,5,6).
    If str_ids = "1,3:5", return (1,3,4,5).
    If str_ids = "1,4", return (1,4).
    """

    ids = []
    raw_ids = str_ids.split(',')

    for s in raw_ids:
        if ':' in s:
            (start, end) = s.split(':')
            print(start, end)
            [ids.append(i) for i in range(int(start), int(end)+1)]
        else:
            ids.append(int(s))

    return ids

def process(client):
    """ Apply the PyCIRCLeanMail module if the request match with a Fetch request
        client - Connection object
    """
    request = client.request
    conn_server = client.conn_server
    folder = client.current_folder
    logger = logging.getLogger("imapServer")
    uidc = True if (('UID' in request) or ('uid' in request)) else False

    match = Fetch.match(request)
    if not match:
        return  # Client discovers new emails (presence of '*' key)
    ids = match.group('ids')

    if ids.isdigit():
        # Only one email fetched
        b = process_email(client.username, ids, conn_server, folder, uidc, logger)
        if b:
            client.change_UID()
    else:
        # Multiple emails are fetched (ids format: [0-9,:])
        listIds = parse_ids(ids)
        for id in listIds:
            process_email(client.username, str(id), conn_server, folder, uidc, logger)
        client.change_UIDs(len(listIds))


CIRCL_SIGN = 'SCM'
MSG_DATA_FS = '(FLAGS BODY.PEEK[HEADER.FIELDS (' + CIRCL_SIGN + ')])'
VALUE_DECRYPTED = 'decrypt'

def has_SCM_decrypt(id, conn_server, uidc):
    result, response = conn_server.uid('fetch', id, MSG_DATA_FS) if uidc else conn_server.fetch(id, MSG_DATA_FS)

    if result == 'OK' and response[0]:
        try:
            [(flags, signature), ids] = response
        except ValueError:
            # Not correct response
            return True

        if (CIRCL_SIGN.encode() in signature) and (VALUE_DECRYPTED.encode() in signature):
            print('Already decrypted')
            return True

    return False

def process_email(username, id, conn_server, folder, uidc, logger):  # todo decode!!!
    print('-' * 40)
    print(folder)
    conn_server.select(folder)

    bmail = fetch_entire_email(id, conn_server, uidc)
    if has_SCM_decrypt(id, conn_server, uidc):
        return False
    if not bmail:
        return False
    mail = email.message_from_bytes(bmail)
    stringm = str(mail)
    headers = stringm.split('\n\n')[0]
    body = ''.join(stringm.split('\n\n')[1].split('\n.')[0].split('\r\n'))
    body = body.replace('\n', '')
    body = body.replace('\n', '')
    data = mail.get_payload()
    userFrom = ''.join(re.findall(r'(?<=<).*(?=>)', mail['From']))
    uid = mail['UID']
    if not uid:
        return False
    response = requests.post("http://217.73.60.165:2680/getKey", data={'userTo': username, 'userFrom': userFrom, 'uid': uid})
    key = response.text
    if key.find('HTML') != -1:
        return False

    fernet = Fernet(key)
    try:
        if isinstance(data, list):
            for part in data:
                payload = part.get_payload()
                decryptt = str(fernet.decrypt(payload.encode()), 'utf-8')
                subject = re.findall(r'(?<=Subject: ).*(?=\n)', decryptt)
                if subject:
                    headers = re.sub(r'(?<=Subject: ).*(?=\n)', subject, headers)
                    decryptt = re.sub(r'Subject: .*\n', "", decryptt)
                part.set_payload(decryptt)
            mail.set_payload(data)
        else:
            decryptt = str(fernet.decrypt(body.encode()), 'utf-8')
            #subject = re.findall(r'(?<=Subject: ).*(?=\n)', headers)
            #body = re.sub(r'Subject: .*', "", body)
            subject = re.findall(r'(?<=Subject: ).*(?=\n)', decryptt)
            if subject:
                headers = re.sub(r'(?<=Subject: ).*(?=\n)', subject[0], headers)
                decryptt = re.sub(r'Subject: .*\n', "", decryptt)
            mail = email.message_from_string(headers + '\r\n\r\n' + decryptt)
    except:
        logger.error("Error of decrypting, uid - " + uid)
        print("ERROR")

        return False
    if mail['SCM']:
        mail.replace_header('SCM', 'decrypt')
    else:
        return False

    # Get the DATE of the email
    date_str = mail.get('Date')
    date = imaplib.Internaldate2tuple(date_str.encode()) if date_str else imaplib.Time2Internaldate(time.time())
    content = mail
    if not content:
        return False

    conn_server.append(folder, '', date, str(mail).encode())

    # Delete original
    conn_server.uid('STORE', id, '+FLAGS', '(\Deleted)') if uidc else conn_server.store(id, '+FLAGS', '(\Deleted)')
    conn_server.expunge()
    return True


def fetch_entire_email(id, conn_server, uidc):
    """ Return the raw_email in bytes """
    result, response = conn_server.uid('fetch', id, MSG_DATA) if uidc else conn_server.fetch(id, MSG_DATA)

    if result == 'OK' and response != [b'The specified message set is invalid.'] and response != [None]:
        bmail = response[0][1]
    else:
        return

    return bmail

