from scapy.all import sniff
from datetime import datetime

LOG_FILE = "packet_log.txt"

def process_packet(packet):
    log_entry = f"[{datetime.now()}] "
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        log_entry += f"IP Packet: {src} -> {dst}, Protocol: {proto}"
        if packet.haslayer("TCP") or packet.haslayer("UDP"):
            sport = packet.sport
            dport = packet.dport
            log_entry += f", Ports: {sport} -> {dport}"
    else:
        log_entry += "Non-IP Packet"
    
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def main():
    print("Starting packet capture... (Press Ctrl+C to stop)")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()