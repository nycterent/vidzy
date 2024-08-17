from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from urllib.parse import urlparse
import base64
import datetime
import requests
import json
import hashlib

recipient_url = "https://fosstodon.org/@vidzy"
recipient_inbox = "https://fosstodon.org/@vidzy/inbox"

sender_url = "https://vidzytesting.pythonanywhere.com/users/zampano"
sender_key = "https://vidzytesting.pythonanywhere.com/users/zampano#main-key"

activity_id = "https://vidzytesting.pythonanywhere.com/users/zampano/follows/test"


# The following is to sign the HTTP request as defined in HTTP Signatures.
with open("private.pem", 'rb') as f:
    private_key_text = f.read() # load from file

private_key = crypto_serialization.load_pem_private_key(
    private_key_text,
    password=None,
    backend=crypto_default_backend()
)

current_date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

recipient_parsed = urlparse(recipient_inbox)
recipient_host = recipient_parsed.netloc
recipient_path = recipient_parsed.path

#signature_text = b'(request-target): post %s\nhost: %s\ndate: %s' % recipient_path.encode('utf-8'), recipient_host.encode('utf-8'), date.encode('utf-8')
signature_text = '(request-target): post {0}\nhost: {1}\ndate: {2}'.format( recipient_path.encode('utf-8'), recipient_host.encode('utf-8'), current_date.encode('utf-8') ).encode()

raw_signature = private_key.sign(
    signature_text,
    padding.PKCS1v15(),
    hashes.SHA256()
)

signature_header = 'keyId="{0}",algorithm="rsa-sha256",headers="(request-target) host date",signature="{1}"'.format( sender_key, base64.b64encode(raw_signature).decode('utf-8') ).encode()

headers = {
    'Date': current_date,
    'Content-Type': 'application/activity+json',
    'Host': recipient_host,
    'Signature': signature_header
}

# Now that the header is set up, we will construct the message
follow_request_message = {
    "@context": "https://www.w3.org/ns/activitystreams",
    "id": activity_id,
    "type": "Follow",
    "actor": sender_url,
    "object": recipient_url
}
follow_request_json = json.dumps(follow_request_message)
digest = base64.b64encode(hashlib.sha256(follow_request_json.encode('utf-8')).digest())

# signature information is now
signature_text = '(request-target): post {0}\ndigest: SHA-256={1}\nhost: {2}\ndate: {3}'.format(recipient_path.encode('utf-8'), digest, recipient_host.encode('utf-8'), current_date.encode('utf-8')).encode()

raw_signature = private_key.sign(
    signature_text,
    padding.PKCS1v15(),
    hashes.SHA256()
)

signature_header = 'keyId="{0}",algorithm="rsa-sha256",headers="(request-target) digest host date",signature="{1}"'.format( sender_key, base64.b64encode(raw_signature).decode('utf-8') ).encode()

headers = {
    'Date': current_date,
    'Content-Type': 'application/activity+json',
    'Host': recipient_host,
    'Digest': "SHA-256="+digest.decode('utf-8'),
    'Signature': signature_header
}

r = requests.post(recipient_inbox, headers=headers, json=follow_request_message)