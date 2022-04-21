#Tar_Slip
import tarfile
import os.path

with tarfile.open('archive.zip') as tar:
    #BAD : This could write any file on the filesystem.
    for entry in tar:
        tar.extract(entry, "/tmp/unpack/")

    # GOOD: Check that entry is safe
    for entry in tar:
        if os.path.isabs(entry.name) or ".." in entry.name:
            raise ValueError("Illegal tar archive entry")
        tar.extract(entry, "/tmp/unpack/")

#Code_Injection
import base64


def setname(data):
    return None


def code_execution(request):
    if request.method == 'POST':
        first_name = base64.decodestring(request.POST.get('first_name', ''))
        #BAD -- Allow user to define code to be run.
        exec("setname('%s')" % first_name)


def code_execution(request):
    if request.method == 'POST':
        first_name = base64.decodestring(request.POST.get('first_name', ''))
        #GOOD --Call code directly
        setname(first_name)

#SQL_Injection
from django.conf.urls import url
from django.db import connection


def show_user(request, username):
    with connection.cursor() as cursor:
        # BAD -- Using string formatting
        cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
        user = cursor.fetchone()

        # BAD -- Manually quoting placeholder (%s)
        cursor.execute("SELECT * FROM users WHERE username = '%s'", username)
        user = cursor.fetchone()

        # GOOD -- Using parameters
        cursor.execute("SELECT * FROM users WHERE username = %s", username)
        user = cursor.fetchone()


urlpatterns = [url(r'^users/(?P<username>[^/]+)$', show_user)]

#Path_Injection
def user_picture1(request):
    """A view that is vulnerable to malicious file access."""
    filename = request.GET.get('p')
    # BAD: This could read any file on the file system
    data = open(filename, 'rb').read()
    return None


def user_picture2(request):
    """A view that is vulnerable to malicious file access."""
    base_path = '/server/static/images'
    filename = request.GET.get('p')
    # BAD: This could still read any file on the file system
    data = open(os.path.join(base_path, filename), 'rb').read()
    return None


def user_picture3(request):
    """A view that is not vulnerable to malicious file access."""
    base_path = '/server/static/images'
    filename = request.GET.get('p')
    #GOOD -- Verify with normalised version of path
    fullpath = os.path.normpath(os.path.join(base_path, filename))
    if not fullpath.startswith(base_path):
        raise ValueError("illegal request")
    data = open(fullpath, 'rb').read()
    return None


#Hard Coded Credentials
import hashlib
import binascii


CONFIG_FILE = './config.cfg'


def redirect(data):
    return None


def load_from_config(data):
    return None


def process_request(request):
    password = request.GET["password"]

    # BAD: Inbound authentication made by comparison to string literal
    if password == "myPa55word":
        redirect("login")

    hashed_password = load_from_config('hashed_password',CONFIG_FILE)
    salt = load_from_config('salt', CONFIG_FILE)


    #GOOD: Inbound authentication made by comparing to a hash password from a config file.
    dk = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
    hashed_input = binascii.hexlify(dk)
    if hashed_input == hashed_password:
        redirect("login")


# No Cert Validation
import requests


# Unsafe requests
requests.get('https://semmle.com', verify=False) # UNSAFE
requests.get('https://semmle.com', verify=0) # UNSAFE

# Various safe options
requests.get('https://semmle.com', verify=True) # Explicitly safe
requests.get('https://semmle.com', verify="/path/to/cert/")
requests.get('https://semmle.com') # The default is to verify.


# Wrapper to ensure safety
def make_safe_request(url, verify_cert):
    if not verify_cert:
        raise Exception("Trying to make unsafe request")
    return requests.get(url, verify_cert)


# Secrets in Cookies
from flask import Flask, make_response, request

app = Flask("Leak password")


def render_template(data):
    return None


@app.route('/')
def index():
    password = request.args.get("password")
    resp = make_response(render_template(...))
    resp.set_cookie("password", password)
    return resp


#Stacktrack Exposed
from flask import Flask
import traceback
import logging
app = Flask(__name__)


def do_computation():
    raise Exception("Secret info")


# BAD
@app.route('/bad')
def server_bad():
    try:
        do_computation()
    except Exception as e:
        return traceback.format_exc()


# GOOD
@app.route('/good')
def server_good():
    try:
        do_computation()
    except Exception as e:
        logging.warning(traceback.format_exc())
        return "An internal error has occurred!"


#Unsecure Redirects
from flask import Flask, request, redirect

app = Flask(__name__)

VALID_REDIRECT = "http://cwe.mitre.org/data/definitions/601.html"


@app.route('/')
#Bad Redirect
def hello_bad():
    target = request.args.get('target', '')
    return redirect(target, code=302)

#Good Redirect
def hello_good():
    target = request.args.get('target', '')
    if target == VALID_REDIRECT:
        return redirect(target, code=302)
    else:
        ...# Error


#Weak Ciphers
from Crypto.Cipher import DES, Blowfish

SECRET_KEY = None

cipher = DES.new(SECRET_KEY)


def send_encrypted(channel, message):
    channel.send(cipher.encrypt(message)) # BAD: weak encryption


cipher = Blowfish.new(SECRET_KEY)


def send_encrypted(channel, message):
    channel.send(cipher.encrypt(message)) # GOOD: strong encryption