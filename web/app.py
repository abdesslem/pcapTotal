import subprocess
from flask import Flask
app = Flask(__name__)

def _run(cmd):
  try:
    out = subprocess.check_output('{}'.format(cmd), shell=True, close_fds=True)
  except subprocess.CalledProcessError:
    out = False
  return out


@app.route('/')
def hello_world():
    return '<pre>' + _run('../libs/Dshell/dshell-decode -l') + '</pre>'

if __name__ == '__main__':
    app.run()
