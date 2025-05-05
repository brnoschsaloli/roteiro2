import socket
import subprocess
import sys
import whois
import dns.resolver
import shutil
import webtech
import builtwith

# === PortScan Module ===

def guess_os_from_banner(banner):
    banner_lower = banner.lower()
    if "windows" in banner_lower:
        return "Possivelmente Windows"
    elif any(x in banner_lower for x in ["ubuntu", "debian", "linux", "centos", "fedora"]):
        return "Possivelmente Linux"
    elif any(x in banner_lower for x in ["freebsd", "openbsd", "netbsd"]):
        return "Possivelmente BSD"
    else:
        return "Sistema operacional não identificado"

def scan_port_tcp(host, port, timeout=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except socket.timeout:
        return "filtered", f"TCP {port}: Filtrada (Timeout)"
    except ConnectionRefusedError:
        return "closed", None
    except Exception:
        return "closed", None
    else:
        try:
            s.send(b'\n')
            banner = s.recv(2048).decode('utf-8', errors='ignore').strip()
        except Exception:
            banner = ""
        os_guess = guess_os_from_banner(banner) if banner else 'Não identificado'
        return "open", f"TCP {port}: Aberta - Banner: {banner or 'N/A'} | OS: {os_guess}"
    finally:
        s.close()

def scan_port_udp(host, port, timeout=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b'', (host, port))
        data, _ = s.recvfrom(1024)
    except socket.timeout:
        return "filtered", f"UDP {port}: Open|Filtered (Sem resposta)"
    except Exception:
        return "closed", None
    else:
        banner = data.decode('utf-8', errors='ignore').strip()
        return "open", f"UDP {port}: Aberta - Banner: {banner or 'N/A'}"
    finally:
        s.close()

def port_scan(host, start, end, protocol='tcp'):
    print(f"Iniciando PortScan em {host} ({protocol.upper()}) de {start} a {end}...")
    closed = 0
    for port in range(start, end + 1):
        if protocol == 'tcp':
            status, info = scan_port_tcp(host, port)
        else:
            status, info = scan_port_udp(host, port)
        if status == 'open' and info:
            print(info)
        else:
            closed += 1
    print(f"Portas fechadas/filtradas: {closed}\n")

# === BuiltWith Module ===

def builtwith_scan(url):
    try:
        results = builtwith.parse(url)
        print(f"Tecnologias detectadas em {url}:")
        for tech_type, items in results.items():
            print(f"{tech_type}:")
            for item in items:
                print(f" - {item}")
        print()
    except Exception as e:
        print(f"Erro BuiltWith: {e}")

# === WHOIS Module ===

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
    except Exception as e:
        print(f"Erro WHOIS: {e}")
        return
    for k, v in w.items():
        print(f"{k}: {v}")
    print()

# === DNS Enumeration Module ===

def dns_enumeration(domain):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    results = {}
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"\n[+] DNS Enumeration for: {domain}")
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            print(f"\n{rtype} records:")
            records = [str(ans) for ans in answers]
            for record in records:
                print(f" - {record}")
            results[rtype] = records
        except dns.resolver.NoAnswer:
            print(f"[-] No {rtype} record found.")
        except dns.resolver.NXDOMAIN:
            print("[-] Domain does not exist.")
            break
        except dns.exception.DNSException as e:
            print(f"[!] Error retrieving {rtype} record: {e}")
    
# === WebTech Module ===

def web_tech_scan(url):
    try:
        wt = webtech.WebTech(options={'json': True})
        report = wt.start_from_url(url)
        print(f"\nTecnologias detectadas em {url}:")
        print(f"Servidor: {report.get('server', 'Não identificado')}")
        print("Tecnologias:")
        for tech in report['tech']:
            print(f" - {tech['name']} ({tech.get('version', 'versão desconhecida')})")
        print()
    except Exception as e:
        print(f"Erro WebTech: {e}")

# === CLI Interface ===

def main():
    while True:
        print("=== Recon CLI Toolkit ===")
        print("1) PortScan")
        print("2) BuiltWith Scan")
        print("3) WHOIS Lookup")
        print("4) DNS Enumeration")
        print("5) WebTech Scan")
        print("0) Sair")
        choice = input("Escolha uma opção: ")

        if choice == '1':
            h = input("Host/IP: ")
            p1 = int(input("Porta inicial: "))
            p2 = int(input("Porta final: "))
            proto = input("Protocolo (tcp/udp): ")
            port_scan(h, p1, p2, proto)
        elif choice == '2':
            url = input("URL alvo para BuiltWith: ")
            builtwith_scan(url)
        elif choice == '3':
            d = input("Domínio para WHOIS: ")
            whois_lookup(d)
        elif choice == '4':
            d = input("Domínio para DNS Enum: ")
            dns_enumeration(d)
        elif choice == '5':
            t = input("URL alvo para WebTech: ")
            web_tech_scan(t)
        elif choice == '0':
            print("Saindo...")
            sys.exit(0)
        else:
            print("Opção inválida. Tente novamente.\n")

if __name__ == '__main__':
    main()
