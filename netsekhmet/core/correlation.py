from .database import db_session, Host, Port, Vulnerability
from .utils import log
from .scope import check_scope

EXPLOIT_MAP = {
    "eternalblue_real": {"cve":"CVE-2017-0144","ports":[445],"cvss":9.8},
    "log4shell": {"cve":"CVE-2021-44228","ports":[80,443,8080],"cvss":10.0},
    "zerologon": {"cve":"CVE-2020-1472","ports":[135,445],"cvss":10.0},
    "proxyshell": {"cve":"CVE-2021-34473","ports":[443],"cvss":9.8},
    "spring4shell": {"cve":"CVE-2022-22965","ports":[8080],"cvss":9.8},
    "bluekeep": {"cve":"CVE-2019-0708","ports":[3389],"cvss":9.8},
    "smbghost": {"cve":"CVE-2020-0796","ports":[445],"cvss":10.0},
    "vcenter_rce": {"cve":"CVE-2021-21972","ports":[443,8443],"cvss":9.8},
    "f5_rce": {"cve":"CVE-2022-1388","ports":[443,8443],"cvss":9.8},
    "printnightmare": {"cve":"CVE-2021-34527","ports":[445],"cvss":8.8},
    "confluence_rce": {"cve":"CVE-2022-26134","ports":[8090,80,443],"cvss":9.8},
    "proxynotshell": {"cve":"CVE-2022-41040","ports":[443],"cvss":8.8},
    "struts2_rce": {"cve":"CVE-2017-5638","ports":[8080,80,443],"cvss":10.0},
    "vmware_workspace_rce": {"cve":"CVE-2022-22954","ports":[443,8443],"cvss":9.8},
    "dirtypipe": {"cve":"CVE-2022-0847","ports":[],"cvss":7.8},
    "cacti_rce": {"cve":"CVE-2022-46169","ports":[80,443],"cvss":9.8},
    "zimbra_rce": {"cve":"CVE-2022-27925","ports":[443,7071],"cvss":9.8},
    "papercut_rce": {"cve":"CVE-2023-27350","ports":[9191],"cvss":9.8},
    "moveit_rce": {"cve":"CVE-2023-34362","ports":[443,8443],"cvss":9.8},
    "screenconnect_auth_bypass": {"cve":"CVE-2024-1709","ports":[8041],"cvss":9.8},
    "teamcity_auth_bypass": {"cve":"CVE-2023-33105","ports":[8111],"cvss":9.8},
    "log4j2_rce": {"cve":"CVE-2021-45105","ports":[80,443,8080],"cvss":7.5},
    "exchange_proxylogon": {"cve":"CVE-2021-26855","ports":[443],"cvss":9.8},
    "drupalgeddon2": {"cve":"CVE-2018-7600","ports":[80,443],"cvss":9.8},
    "shellshock": {"cve":"CVE-2014-6271","ports":[80,443],"cvss":9.8},
    "heartbleed_scan": {"cve":"CVE-2014-0160","ports":[443],"cvss":5.0},
    "thinkphp_rce": {"cve":"CVE-2018-20062","ports":[80,443],"cvss":9.8},
    "apache_path_traversal": {"cve":"CVE-2021-41773","ports":[80,443],"cvss":7.5},
    "wordpress_admin_shell": {"cve":"CVE-2020-XXXX","ports":[80,443],"cvss":7.5},
    "jenkins_rce": {"cve":"CVE-2018-1000861","ports":[8080,80,443],"cvss":9.8},
}

class CorrelationEngine:
    @staticmethod
    def suggest_attacks(target_ip):
        with db_session() as db:
            host = db.query(Host).filter_by(ip_address=target_ip).first()
            if not host: return []
            open_ports = {p.port_number for p in db.query(Port).filter_by(host_id=host.id, state='open')}
            suggestions = []
            for name, info in EXPLOIT_MAP.items():
                if not info['ports'] or any(port in open_ports for port in info['ports']):
                    suggestions.append({"module":name, "cve":info['cve'], "reason":f"Open ports {info['ports']}" if info['ports'] else "Local", "cvss":info['cvss']})
            suggestions.sort(key=lambda x: x['cvss'], reverse=True)
            return suggestions

    @staticmethod
    def run_auto(target_ip):
        if not check_scope(target_ip, "auto_exploit"): return
        suggestions = CorrelationEngine.suggest_attacks(target_ip)
        if not suggestions: log("INFO", "No suggestions"); return
        from .exploit_engine import ExploitEngine
        ExploitEngine.load_exploits()
        for s in suggestions:
            log("INFO", f"Attempting {s['module']} ...")
            result = ExploitEngine.run_exploit(s['module'], rhost=target_ip)
            if result and result.success:
                log("SUCCESS", f"{s['module']} succeeded! Session: {result.session_id}")
            else:
                log("WARNING", f"{s['module']} failed")
