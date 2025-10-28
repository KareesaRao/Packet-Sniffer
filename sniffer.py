from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest # You might need to run: pip install scapy_http
import scapy.all as scapy

def sniff_packets(interface):
    """
    Sniffs packets on a given network interface.
    'prn' specifies a callback function to run for every packet.
    'store=0' means Scapy won't store packets in memory.
    """
    print(f"[+] Sniffing on interface {interface}...")
    scapy.sniff(iface=interface, store=0, prn=process_packet)

def process_packet(packet):
    """
    Parses and displays key info from IP, TCP, UDP, and HTTP packets.
    """

    # Check if it's an IP packet
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Check for TCP
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"[TCP] {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")

            # Check for HTTP (which runs on top of TCP)
            if packet.haslayer(HTTPRequest):
                http_layer = packet.getlayer(HTTPRequest)

                # Check for Host and Path (which are bytes, so we decode)
                host = http_layer.Host.decode() if http_layer.Host else "Unknown"
                path = http_layer.Path.decode() if http_layer.Path else ""
                method = http_layer.Method.decode() if http_layer.Method else "Unknown"

                print(f"    [HTTP] {method} Request: {host}{path}")

                # Check for raw payload (e.g., form data)
                if http_layer.payload:
                    payload = bytes(http_layer.payload).decode('utf-8', 'ignore')
                    # Look for common login keywords
                    if "user" in payload.lower() or "pass" in payload.lower() or "login" in payload.lower():
                        print(f"    [!] Possible credentials found: {payload[:100]}...")

        # Check for UDP
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"[UDP] {src_ip}:{udp_layer.sport} -> {dst_ip}:{udp_layer.dport}")


# --- Main execution ---
if __name__ == "__main__":
    # IMPORTANT: You need to find your network interface name.
    # On Windows: run 'ipconfig' (Look for "Ethernet adapter" or "Wi-Fi adapter")
    # On Mac/Linux: run 'ifconfig' or 'ip a' (Look for 'en0', 'eth0', 'wlan0', etc.)
    
    # Replace "Wi-Fi" with your actual interface name
    INTERFACE_TO_SNIFF = "WiFi" 
    
    try:
        sniff_packets(INTERFACE_TO_SNIFF)
    except PermissionError:
        print("\n[!] Error: Root/Administrator privileges are required to sniff packets.")
        print("Try running the script with 'sudo' (Linux/Mac) or as Administrator (Windows).")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")