import subprocess
import sqlite3
import hashlib
import time
import os
from flask import send_from_directory
from werkzeug import secure_filename
from flask import Flask, render_template,session, g, redirect, url_for, request, flash
from api import api
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
app.register_blueprint(api)

# This is the path to the upload directory
app.config['UPLOAD_FOLDER'] = 'uploads/'
# These are the extension that we are accepting to be uploaded
app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 'cap', 'pcap'])

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

@app.route('/stream/<filename>')
def followstream(filename):
    command = '../libs/Dshell/dshell-decode -d followstream '+ os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return '<pre>' + _run(command) + '</pre>'

@app.route('/netflow/<filename>')
def netflow(filename):
    command = '../libs/Dshell/dshell-decode -d netflow '+ os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return '<pre>' + _run(command) + '</pre>'

@app.route('/dns/<filename>')
def dns(filename):
    command = '../libs/Dshell/dshell-decode -d dns '+ os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return '<pre>' + _run(command) + '</pre>'

@app.route('/extract/<filename>')
def extract(filename):
    command = '../libs/Dshell/dshell-decode -d rip-http '+ os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return '<pre>' + _run(command) + '</pre>'


@app.route('/httpdump/<filename>')
def httpdump(filename):
    command = '../libs/Dshell/dshell-decode -d httpdump '+ os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return '<pre>' + _run(command) + '</pre>'

@app.route('/ip/<filename>')
def ip(filename):
    command = '../libs/Dshell/dshell-decode -d ip '+ os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return '<pre>' + _run(command) + '</pre>'

@app.route('/writer/<filename>')
def writer(filename):
    command = '../libs/Dshell/dshell-decode -d writer '+ os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return '<pre>' + _run(command) + '</pre>'

@app.route('/synrst/<filename>')
def synrst(filename):
    command = '../libs/Dshell/dshell-decode -d synrst '+ os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return '<pre>' + _run(command) + '</pre>'

@app.route('/track/<filename>')
def track(filename):
    command = '../libs/Dshell/dshell-decode -d track '+ os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return '<pre>' + _run(command) + '</pre>'


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



@app.route('/users', methods=['POST', 'GET'])
def users():
    '''
    returns users and get posts request : can edit or add user in page.
    this funtction uses sqlite3
    '''
    if 'logged_in' in session:
        if session['su'] != 'Yes':
            return abort(403)

        try:
            trash = request.args.get('trash')
        except KeyError:
            trash = 0

        su_users = query_db("SELECT COUNT(id) as num FROM users "
                            "WHERE su='Yes'", [], one=True)

        if request.args.get('token') == session.get('token') and \
                int(trash) == 1 and request.args.get('userid') and \
                request.args.get('username'):
            nb_users = query_db("SELECT COUNT(id) as num FROM users", [],
                                one=True)

            if nb_users['num'] > 1:
                if su_users['num'] <= 1:
                    su_user = query_db("SELECT username FROM users "
                                       "WHERE su='Yes'", [], one=True)

                    if su_user['username'] == request.args.get('username'):
                        flash(u'Can\'t delete the last admin user : %s' %
                              request.args.get('username'), 'error')
                        return redirect(url_for('lwp_users'))

                g.db.execute("DELETE FROM users WHERE id=? AND username=?",
                             [request.args.get('userid'),
                              request.args.get('username')])
                g.db.commit()
                flash(u'Deleted %s' % request.args.get('username'), 'success')
                return redirect(url_for('lwp_users'))

            flash(u'Can\'t delete the last user!', 'error')
            return redirect(url_for('lwp_users'))

        if request.method == 'POST':
            users = query_db('SELECT id, name, username, su FROM users '
                             'ORDER BY id ASC')

            if request.form['newUser'] == 'True':
                if not request.form['username'] in \
                        [user['username'] for user in users]:
                    if re.match('^\w+$', request.form['username']) and \
                            request.form['password1']:
                        if request.form['password1'] == \
                                request.form['password2']:
                            if request.form['name']:
                                if re.match('[a-z A-Z0-9]{3,32}',
                                            request.form['name']):
                                    g.db.execute(
                                        "INSERT INTO users "
                                        "(name, username, password) "
                                        "VALUES (?, ?, ?)",
                                        [request.form['name'],
                                         request.form['username'],
                                         hash_passwd(
                                             request.form['password1'])])
                                    g.db.commit()
                                else:
                                    flash(u'Invalid name!', 'error')
                            else:
                                g.db.execute("INSERT INTO users "
                                             "(username, password) VALUES "
                                             "(?, ?)",
                                             [request.form['username'],
                                              hash_passwd(
                                                  request.form['password1'])])
                                g.db.commit()

                            flash(u'Created %s' % request.form['username'],
                                  'success')
                        else:
                            flash(u'No password match', 'error')
                    else:
                        flash(u'Invalid username or password!', 'error')
                else:
                    flash(u'Username already exist!', 'error')

            elif request.form['newUser'] == 'False':
                if request.form['password1'] == request.form['password2']:
                    if re.match('[a-z A-Z0-9]{3,32}', request.form['name']):
                        if su_users['num'] <= 1:
                            su = 'Yes'
                        else:
                            try:
                                su = request.form['su']
                            except KeyError:
                                su = 'No'

                        if not request.form['name']:
                            g.db.execute("UPDATE users SET name='', su=? "
                                         "WHERE username=?",
                                         [su, request.form['username']])
                            g.db.commit()
                        elif request.form['name'] and \
                                not request.form['password1'] and \
                                not request.form['password2']:
                            g.db.execute("UPDATE users SET name=?, su=? "
                                         "WHERE username=?",
                                         [request.form['name'], su,
                                          request.form['username']])
                            g.db.commit()
                        elif request.form['name'] and \
                                request.form['password1'] and \
                                request.form['password2']:
                            g.db.execute("UPDATE users SET "
                                         "name=?, password=?, su=? WHERE "
                                         "username=?",
                                         [request.form['name'],
                                          hash_passwd(
                                              request.form['password1']),
                                          su, request.form['username']])
                            g.db.commit()
                        elif request.form['password1'] and \
                                request.form['password2']:
                            g.db.execute("UPDATE users SET password=?, su=? "
                                         "WHERE username=?",
                                         [hash_passwd(
                                             request.form['password1']),
                                          su, request.form['username']])
                            g.db.commit()

                        flash(u'Updated', 'success')
                    else:
                        flash(u'Invalid name!', 'error')
                else:
                    flash(u'No password match', 'error')
            else:
                flash(u'Unknown error!', 'error')

        users = query_db("SELECT id, name, username, su FROM users "
                         "ORDER BY id ASC")
        nb_users = query_db("SELECT COUNT(id) as num FROM users", [], one=True)
        su_users = query_db("SELECT COUNT(id) as num FROM users "
                            "WHERE su='Yes'", [], one=True)

        return render_template('users.html')
    return render_template('login.html')



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

@app.route('/modules')
def hello_world():
    return '<pre>' + _run('../libs/Dshell/dshell-decode -l') + '</pre>'

if __name__ == '__main__':
    app.run(debug=True)
