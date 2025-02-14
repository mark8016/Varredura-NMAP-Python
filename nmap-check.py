import nmap

def scan_vulnerabilities(target):
    print(f"Escaneando {target} por vulnerabilidades...\n")
    
    # Inicializando o objeto nmap
    nm = nmap.PortScanner()
    
    # Escaneando as portas e serviços
    nm.scan(hosts=target, arguments='-sV')  # '-sV' para detectar versões de serviços
    
    for host in nm.all_hosts():
        print(f"\nHost: {host}")
        for proto in nm[host].all_protocols():
            print(f"Protocolo: {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"Porta: {port}, Serviço: {nm[host][proto][port]['name']}, Versão: {nm[host][proto][port]['version']}")

# Alvo de escaneamento
target = "192.168.1.1"  # Alvo para escanear
scan_vulnerabilities(target)
