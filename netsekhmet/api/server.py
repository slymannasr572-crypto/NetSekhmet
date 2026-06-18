from flask import Flask, jsonify, request
from ..core.database import db_session, Host, Port, Session
from ..core.sessions import SessionManager

app = Flask(__name__)
sm = SessionManager()

@app.route('/api/sessions', methods=['GET'])
def list_sessions():
    return jsonify(sm.list())

@app.route('/api/sessions/<sid>/cmd', methods=['POST'])
def session_cmd(sid):
    data = request.get_json()
    res = sm.send_command(sid, data['command'])
    return jsonify({'result': res})

def start_api(host='0.0.0.0', port=5000):
    app.run(host=host, port=port)
