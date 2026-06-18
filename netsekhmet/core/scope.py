import os, json, ipaddress
from .utils import log
SCOPE_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'scope', 'scope.json')
def load_scope():
    if not os.path.exists(SCOPE_FILE):
        default = {"allowed_ips":[], "allowed_domains":[], "strict":True}
        os.makedirs(os.path.dirname(SCOPE_FILE), exist_ok=True)
        with open(SCOPE_FILE,'w') as f: json.dump(default, f)
        return default
    with open(SCOPE_FILE) as f: return json.load(f)
def save_scope(scope):
    with open(SCOPE_FILE,'w') as f: json.dump(scope, f, indent=2)
def is_in_scope(target):
    scope = load_scope()
    if not scope.get("strict", True): return True
    try:
        ip = ipaddress.ip_address(target)
        for allowed in scope.get("allowed_ips", []):
            if '/' in allowed and ip in ipaddress.ip_network(allowed, strict=False): return True
            elif allowed == str(ip): return True
    except ValueError: pass
    for domain in scope.get("allowed_domains", []):
        if target == domain or target.endswith('.' + domain): return True
    return False
def check_scope(target, op="exploit"):
    if not is_in_scope(target):
        log("ERROR", f"Operation {op} blocked for {target} (out of scope)")
        return False
    return True
