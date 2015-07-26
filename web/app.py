import subprocess
import sqlite3
import hashlib
import time
import os
from flask import send_from_directory
from werkzeug import secure_filename
from flask import Flask, render_template,session, g, redirect, url_for, request, flash
from api import api
from user import user
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.utils import *
import packetParser
import streamParser
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

# configuration
config = configparser.SafeConfigParser()
config.readfp(open('pt.conf'))

SECRET_KEY = '\xb13\xb6\xfb+Z\xe8\xd1n\x80\x9c\xe7KM' \
             '\x1c\xc1\xa7\xf8\xbeY\x9a\xfa<.'

DEBUG = config.getboolean('global', 'debug')
DATABASE = config.get('database', 'file')
ADDRESS = config.get('global', 'address')
PORT = int(config.get('global', 'port'))

app = Flask(__name__)
app.config.from_object(__name__)
app.register_blueprint(api)
app.register_blueprint(user)
# This is the path to the upload directory
app.config['UPLOAD_FOLDER'] = 'uploads/'
# These are the extension that we are accepting to be uploaded
app.config['ALLOWED_EXTENSIONS'] = set(['pcapng','cap', 'pcap'])

# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

# Route that will process the file upload
@app.route('/upload', methods=['POST'])
def upload():
    # Get the name of the uploaded file
    file = request.files['file']
    # Check if the file is one of the allowed types/extensions
    if file and allowed_file(file.filename):
        # Make the filename safe, remove unsupported chars
        filename = secure_filename(file.filename)
        # Move the file form the temporal folder to
        # the upload folder we setup
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        # Redirect the user to the uploaded_file route, which
        # will basicaly show on the browser the uploaded file
        return redirect(url_for('track',
                                filename=filename))
# This route is expecting a parameter containing the name
# of a file. Then it will locate that file on the upload
# directory and show it on the browser, so if the user uploads
# an image, that image is going to be show after the upload
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)
@app.route('/analyzer/<filename>')
def analyzer(filename):
    try:
        filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        packets = rdpcap(filename)
        return redirect(url_for('home'))       
    except Exception ,e:
        return "can't read pcap file" + str(e)
    #packets.summary()
    s = packets.sessions()
    for k, v in s.iteritems():
        print k



def connect_db():
    '''
    SQLite3 connect function
    '''

    return sqlite3.connect(app.config['DATABASE'])


@app.before_request
def before_request():
    '''
    executes functions before all requests
    '''
    g.db = connect_db()


@app.teardown_request
def teardown_request(exception):
    '''
    executes functions after all requests
    '''
    if hasattr(g, 'db'):
        g.db.close()


def _run(cmd):
  try:
    out = subprocess.check_output('{}'.format(cmd), shell=True, close_fds=True)
  except subprocess.CalledProcessError:
    out = False
  return out

def hash_passwd(passwd):
    return hashlib.sha512(passwd.encode()).hexdigest()


@app.route('/home')
@app.route('/')
def home():
    if 'username' in session :
	 pr = packetParser.parser()
         pkts = pr.reader('uploads/file.pcap')
         return render_template('packets.html',packets=pkts)  # render a template
    return render_template('login.html')

@app.route('/sessions')
def sessions():
    if 'username' in session :
         ses=streamParser.getSessions('uploads/file.pcap')
         return render_template('sessions.html',sessions=ses)  # render a template
    return render_template('login.html')

def query_db(query, args=(), one=False):
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
          for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv
@app.route('/about')
def about():
    '''
    about page
    '''

    if 'logged_in' in session:
        return render_template('about.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

def get_token():
    return hashlib.md5(str(time.time()).encode()).hexdigest()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        request_username = request.form['username']
        request_passwd = hash_passwd(request.form['password'])

        current_url = request.form['url']

        user = query_db('select name, username, su from users where username=?'
                        'and password=?', [request_username, request_passwd],
                        one=True)

        if user:
            session['logged_in'] = True
            session['token'] = get_token()
            session['last_activity'] = int(time.time())
            session['username'] = user['username']
            session['name'] = user['name']
            session['su'] = user['su']
            flash(u'You are logged in!', 'success')

            if current_url == url_for('login'):
                return redirect(url_for('home'))
            return redirect(current_url)

        flash(u'Invalid username or password!', 'error')
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
