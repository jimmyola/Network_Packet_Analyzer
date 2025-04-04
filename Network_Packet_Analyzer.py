import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet [scapy.IP].src
        dst_ip = packet[scapy.IP].proto
        protcol = packet[scapy.IP].proto

    print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | protocol" {protocol} )
    
    if packet.haslayer(scapy.TCP):
    try:
        payload = packet[scapy.Raw].load
        decoded_payload = payload.decode('utf-8', 'ignore')
        Print (f"TCP Payload (first 50 characters): {decoded_payload[:50]}") 
    except (IndexError, UnicodeDecodeError):
        print("unablle to decode TCP payload.")
                                                             
        elif pscket_haslayer(scapy.UDP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                Print(f"TCP Payload (first 50 characters): {decoded_payload[:50]}") 
        except (IndexError, UnicodeDecodeError):
                print("unablle to decode UDP payload.")
                
def start_sniffing():
    scapy.sniff(storeFalse, pre=pocket_callback)

    start_sniffig 