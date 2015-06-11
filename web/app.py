import subprocess
import sqlite3
import hashlib
import time
from flask import Flask, render_template,session, g, redirect, url_for, request, flash

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

# configuration
config = configparser.SafeConfigParser()
config.readfp(open('lwp.conf'))

SECRET_KEY = '\xb13\xb6\xfb+Z\xe8\xd1n\x80\x9c\xe7KM' \
             '\x1c\xc1\xa7\xf8\xbeY\x9a\xfa<.'

DEBUG = config.getboolean('global', 'debug')
DATABASE = config.get('database', 'file')
ADDRESS = config.get('global', 'address')
PORT = int(config.get('global', 'port'))

app = Flask(__name__)
app.config.from_object(__name__)

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
         return render_template('index.html')  # render a template
    return render_template('login.html')

def query_db(query, args=(), one=False):
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
          for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


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

@app.route('/hello')
def hello_world():
    return '<pre>' + _run('../libs/Dshell/dshell-decode -l') + '</pre>'

if __name__ == '__main__':
    app.run(debug=True)
