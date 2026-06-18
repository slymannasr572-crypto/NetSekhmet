import sys, os, time, random, logging, ipaddress, re, secrets, base64, socket, struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .config import Colors

__version__ = "14.0.0"
logger = logging.getLogger('NetSekhmet')
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler(); ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)-7s] %(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(ch)

def log(level, msg):
    lvl=level.upper()
    if lvl=="SUCCESS": logger.info(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    elif lvl=="ERROR": logger.error(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    elif lvl=="WARNING": logger.warning(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
    elif lvl=="INFO": logger.info(f"{Colors.CYAN}[*] {msg}{Colors.RESET}")
    else: logger.info(msg)

def validate_target(target):
    try: ipaddress.ip_address(target); return True
    except ValueError: pass
    return re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', target) is not None

def get_local_ip(remote="8.8.8.8"):
    try:
        import netifaces
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                ip=addr['addr']
                if ip!='127.0.0.1': return ip
    except: pass
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((remote,80)); ip=s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

CURVE = ec.SECP256R1()
def generate_ecdh_key_pair():
    private = ec.generate_private_key(CURVE, default_backend())
    public = private.public_key()
    return private, public

def derive_shared_key(private_key, peer_public_bytes):
    try:
        peer_public = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, peer_public_bytes)
    except:
        peer_public = serialization.load_pem_public_key(peer_public_bytes, default_backend())
    shared = private_key.exchange(ec.ECDH(), peer_public)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'netsekhmet-v4')
    return base64.urlsafe_b64encode(hkdf.derive(shared))

def pubkey_fingerprint(pub_key):
    pem = pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pem)
    return base64.b64encode(digest.finalize()).decode()

BANNER = f"""
\033[38;5;46m _   _      _   _   _           _
| \\ | | ___| |_| | | | ___ _ __| |_ __ ___  _ __
|  \\| |/ _ \\ __| |_| |/ _ \\ '__| | '_ ` _ \\| '_ \\
| |\\  |  __/ |_|  _  |  __/ |  | | | | | | |_) |
|_| \\_|\\___|\\__|_| |_|\\___|_|  |_|_| |_| |_| .__/
                                            |_|
 NetSekhmet – v{__version__} | Final Combat Edition\033[0m
"""
