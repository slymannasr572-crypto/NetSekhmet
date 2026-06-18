import os, yaml
from colorama import Fore, Style, init
init(autoreset=True)

class Colors:
    RED=Fore.RED; GREEN=Fore.GREEN; YELLOW=Fore.YELLOW; BLUE=Fore.BLUE
    MAGENTA=Fore.MAGENTA; CYAN=Fore.CYAN; WHITE=Fore.WHITE
    BOLD=Style.BRIGHT; RESET=Style.RESET_ALL

config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "netsekhmet.yml")
os.makedirs(os.path.dirname(config_path), exist_ok=True)
if os.path.exists(config_path):
    with open(config_path) as f: CONFIG = yaml.safe_load(f) or {}
else:
    CONFIG = {"c2":{"host":"0.0.0.0","port":8443,"protocol":"tcp","ssl":True,"key_exchange":"ecdh_secp256r1"}}
