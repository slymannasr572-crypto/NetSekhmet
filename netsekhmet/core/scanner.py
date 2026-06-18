import socket, ssl, concurrent.futures, threading
from .utils import log, validate_target
from .database import db_session, store_host, store_port
from .scope import check_scope

def validate_port_list(port_str):
    parts = port_str.split(',')
    ports = []
    for p in parts:
        p = p.strip()
        if '-' in p:
            start,end = p.split('-')
            ports.extend(range(int(start), int(end)+1))
        else:
            ports.append(int(p))
    return sorted(set(ports))

class PortScanner:
    def __init__(self, target, ports, use_nmap=True, timeout=2.0, max_workers=200, udp=False, service_scan=True):
        if not validate_target(target): raise ValueError("Invalid target")
        if not check_scope(target, "port_scan"): raise PermissionError("Out of scope")
        self.target=target; self.ports=ports; self.use_nmap=use_nmap; self.timeout=timeout
        self.max_workers=max_workers; self.udp=udp; self.service_scan=service_scan
        with db_session() as db: self.host = store_host(db, target)
        self.results={}
    def scan(self):
        log("INFO", f"Scanning {len(self.ports)} ports on {self.target}")
        if self.use_nmap and self._nmap_available():
            try: return self._nmap_scan()
            except Exception as e: log("ERROR", f"Nmap failed: {e}")
        return self._tcp_connect_scan()
    def _nmap_available(self):
        try: import nmap; nmap.PortScanner(); return True
        except: return False
    def _nmap_scan(self):
        import nmap
        nm = nmap.PortScanner()
        proto = "U" if self.udp else "T"
        args = f"-p {','.join(map(str,self.ports))} -s{proto} --open -sV -T4 --script banner -O"
        nm.scan(self.target, arguments=args)
        with db_session() as db:
            for host in nm.all_hosts():
                for proto_key in nm[host].all_protocols():
                    for port in nm[host][proto_key]:
                        info = nm[host][proto_key][port]
                        store_port(db, self.host, port, proto_key, info.get('state','open'), info.get('name',''), info.get('product',''), info.get('version',''))
                        self.results[port] = {"state":info.get('state'),"service":info.get('name'),"banner":info.get('product',''),"proto":proto_key}
        return self.results
    def _tcp_connect_scan(self):
        results={}; lock=threading.Lock()
        def check_port(port):
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(self.timeout)
            try:
                if s.connect_ex((self.target, port))==0:
                    banner=""
                    if self.service_scan: banner=self._grab_banner(s,port)
                    service=self._guess_service(port,banner)
                    with lock: results[port]={"state":"open","service":service,"banner":banner,"proto":"tcp"}
            except: pass
            finally: s.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            list(ex.map(check_port, self.ports))
        self.results=results; return results
    def _grab_banner(self, sock, port):
        try:
            sock.settimeout(2)
            if port==443:
                ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                ssock=ctx.wrap_socket(sock, server_hostname=self.target)
                ssock.send(f"GET / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode())
                banner=ssock.recv(4096).decode(errors='ignore').strip()[:500]; ssock.close(); return banner
            sock.send(b"GET / HTTP/1.0\r\n\r\n"); return sock.recv(4096).decode(errors='ignore').strip()[:500]
        except: return ""
    def _guess_service(self, port, banner):
        if port==22 or "SSH" in banner: return "ssh"
        if port==80: return "http"
        if port==443: return "https"
        if port==445: return "smb"
        if port==3389: return "rdp"
        return "unknown"
