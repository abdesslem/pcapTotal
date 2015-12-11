from flask import jsonify, abort, make_response
from flask.ext.httpauth import HTTPBasicAuth
from flask import Blueprint

api = Blueprint('api', __name__)
auth = HTTPBasicAuth()
tasks = [
    {
        'id': 1,
        'title': u'Buy groceries',
        'description': u'Milk, Cheese, Pizza, Fruit, Tylenol', 
        'done': False
    },
    {
        'id': 2,
        'title': u'Learn Python',
        'description': u'Need to find a good Python tutorial on the web', 
        'done': False
    }
]

@api.route('/todo/api/v1.0/tasks', methods=['GET'])
#@auth.login_required
def get_tasks():
    return jsonify({'tasks': tasks})


@api.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['GET'])
#@auth.login_required
def get_task(task_id):
    task = [task for task in tasks if task['id'] == task_id]
    if len(task) == 0:
        abort(404)
    return jsonify({'task': task[0]})

@api.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

@auth.get_password
def get_password(username):
    if username == 'ask3m':
        return 'ask3m'
    return None

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)



