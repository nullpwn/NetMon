import threading
import csv
import logging
import io
import psutil
import time
import socket
from flask import Flask, jsonify, Response, make_response
from flask_cors import CORS
from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, DNSQR, DNSRR
import argparse

# Flask app initialization
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global constants and variables
TRAFFIC_DATA = []
CPU_USAGE = 0
MEMORY_USAGE = 0
DATA_LOCK = threading.Lock()  # Lock for thread-safe access to TRAFFIC_DATA

# Known protocol mappings
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
    2054: "ARP"  # ARP protocol number (EtherType 0x0806)
}

# Application layer protocol mapping based on port numbers
APPLICATION_PROTOCOLS = {
    (5353, "UDP"): "mDNS",
    (80, "TCP"): "HTTP",
    (443, "TCP"): "HTTPS"
}

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_protocol_name(protocol_number, src_port=None, dst_port=None, layer="TCP"):
    """
    Returns the protocol name based on the protocol number and optional port numbers.
    """
    if protocol_number in PROTOCOLS:
        if src_port and dst_port:
            return APPLICATION_PROTOCOLS.get(
                (src_port, layer),
                APPLICATION_PROTOCOLS.get((dst_port, layer), PROTOCOLS[protocol_number])
            )
        return PROTOCOLS[protocol_number]
    return f"Unknown ({protocol_number})"

def process_arp_packet(pkt):
    """
    Processes ARP packets and returns a dictionary containing packet details.
    """
    arp_src_ip = pkt[ARP].psrc
    arp_dst_ip = pkt[ARP].pdst
    arp_src_mac = pkt[ARP].hwsrc
    arp_dst_mac = pkt[ARP].hwdst
    arp_op_code = pkt[ARP].op

    arp_op = "ARP Request" if arp_op_code == 1 else "ARP Reply" if arp_op_code == 2 else f"ARP Opcode {arp_op_code}"

    # Remove the destination MAC address if it is 00:00:00:00:00:00 in ARP requests
    if arp_dst_mac == "00:00:00:00:00:00":
        detailed_info = f"{arp_op} from {arp_src_ip} ({arp_src_mac}) to {arp_dst_ip}"
    else:
        detailed_info = f"{arp_op} from {arp_src_ip} ({arp_src_mac}) to {arp_dst_ip} ({arp_dst_mac})"

    return {
        "No.": len(TRAFFIC_DATA) + 1,
        "Time": time.strftime('%Y-%m-%d %H:%M:%S'),
        "Source": arp_src_ip,
        "Destination": arp_dst_ip,
        "Protocol": "ARP",
        "Length": len(pkt),
        "Info": arp_op,
        "Detailed Info": detailed_info
    }

def process_ip_packet(pkt):
    """
    Processes IP packets and returns a dictionary containing packet details.
    """
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    protocol = pkt[IP].proto

    src_port, dst_port, layer, info = None, None, None, []

    # Extract transport layer information
    if TCP in pkt:
        layer = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        info.extend([
            f"Flags: {pkt[TCP].flags}",
            f"Window Size: {pkt[TCP].window}",
            f"Sequence Number: {pkt[TCP].seq}",
            f"Acknowledgment Number: {pkt[TCP].ack}",
        ])
        if pkt[TCP].options:
            info.append(f"Options: {pkt[TCP].options}")

    elif UDP in pkt:
        layer = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        info.append(f"Length: {pkt[UDP].len}")

    if DNS in pkt:
        dns_info = process_dns_packet(pkt[DNS])
        info.extend(dns_info)

    protocol_name = get_protocol_name(protocol, src_port, dst_port, layer)
    detailed_info = f"{protocol_name} packet from {ip_src}:{src_port} to {ip_dst}:{dst_port}"

    return {
        "No.": len(TRAFFIC_DATA) + 1,
        "Time": time.strftime('%Y-%m-%d %H:%M:%S'),
        "Source": ip_src,
        "Destination": ip_dst,
        "Protocol": protocol_name,
        "Length": len(pkt),
        "Info": " | ".join(info),
        "Detailed Info": detailed_info
    }

def process_dns_packet(dns_pkt):
    """
    Processes DNS packets and returns a list of detailed information strings.
    """
    info = []

    if dns_pkt.qr == 0:  # DNS query
        for i in range(dns_pkt.qdcount):
            query_name = dns_pkt[DNSQR][i].qname.decode()
            query_type = dns_pkt[DNSQR][i].qtype
            info.append(f"DNS Query: {query_name} | Type: {query_type}")

    elif dns_pkt.qr == 1:  # DNS response
        for i in range(dns_pkt.ancount):
            response_name = dns_pkt[DNSRR][i].rrname.decode()
            response_type = dns_pkt[DNSRR][i].type
            response_data = dns_pkt[DNSRR][i].rdata
            if response_type == 1:  # A record
                info.append(f"DNS Response: {response_name} | A: {response_data}")
            elif response_type == 28:  # AAAA record
                info.append(f"DNS Response: {response_name} | AAAA: {response_data}")
            elif response_type == 5:  # CNAME record
                info.append(f"CNAME: {response_name} -> {response_data}")
            else:
                info.append(f"DNS Response: {response_name} | Type: {response_type} | Data: {response_data}")

    return info

def packet_callback(pkt):
    """
    Callback function that processes each packet captured by scapy.
    """
    try:
        if ARP in pkt:
            packet_info = process_arp_packet(pkt)
        elif IP in pkt:
            packet_info = process_ip_packet(pkt)
        else:
            return  # Skip packets that aren't IP or ARP

        # Thread-safe addition to TRAFFIC_DATA
        with DATA_LOCK:
            TRAFFIC_DATA.append(packet_info)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def get_best_interface():
    """
    Returns the best network interface based on the following priorities:
    1. Active interfaces with both IPv4 and IPv6 addresses.
    2. Active interfaces with an IPv4 address and no IPv6 address.
    3. Active interfaces with an IPv6 address and no IPv4 address.
    Loopback interfaces are excluded from consideration.
    """
    interfaces = psutil.net_if_addrs()
    active_interfaces = psutil.net_if_stats()

    # Store the best interfaces according to the specified priorities
    ipv4_and_ipv6 = None
    ipv4_only = None
    ipv6_only = None

    for interface, addrs in interfaces.items():
        # Skip loopback interfaces
        if interface == 'lo' or interface.startswith('lo'):
            continue
        
        if active_interfaces[interface].isup:
            has_ipv4 = False
            has_ipv6 = False
            for addr in addrs:
                if addr.family == socket.AF_INET:  # Check for an IPv4 address
                    has_ipv4 = True
                if addr.family == socket.AF_INET6:  # Check for an IPv6 address
                    has_ipv6 = True
            if has_ipv4 and has_ipv6:
                ipv4_and_ipv6 = interface  # Highest priority
            elif has_ipv4:
                ipv4_only = interface  # Second priority
            elif has_ipv6:
                ipv6_only = interface  # Third priority

    # Return the best available interface based on the priorities
    if ipv4_and_ipv6:
        return ipv4_and_ipv6
    elif ipv4_only:
        return ipv4_only
    elif ipv6_only:
        return ipv6_only
    return None

def start_sniffing(interface):
    """
    Starts the packet capturing process on the specified network interface.
    """
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except Exception as e:
        logging.error(f"Failed to start packet capture: {e}")

def monitor_system_usage():
    """
    Continuously monitors CPU and memory usage.
    """
    global CPU_USAGE, MEMORY_USAGE
    while True:
        CPU_USAGE = psutil.cpu_percent(interval=1)
        MEMORY_USAGE = psutil.virtual_memory().percent
        time.sleep(5)  # Update every 5 seconds

@app.route('/traffic', methods=['GET'])
def get_traffic():
    """
    Endpoint to retrieve captured traffic data in JSON format.
    """
    with DATA_LOCK:
        recent_data = TRAFFIC_DATA[-500:]  # Send the last 500 entries
    return jsonify(recent_data)

@app.route('/export/csv', methods=['GET'])
def export_csv():
    """
    Endpoint to export captured traffic data as a CSV file.
    """
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Detailed Info"])

        with DATA_LOCK:
            for packet in TRAFFIC_DATA:
                writer.writerow([packet["No."], packet["Time"], packet["Source"], packet["Destination"], packet["Protocol"], packet["Length"], packet["Info"], packet["Detailed Info"]])

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=traffic_data.csv"
        response.headers["Content-type"] = "text/csv"
        return response
    except Exception as e:
        logging.error(f"Error exporting CSV: {e}")
        return Response("Failed to export CSV", status=500)

@app.route('/system-usage', methods=['GET'])
def get_system_usage():
    """
    Endpoint to retrieve current CPU and memory usage.
    """
    return jsonify({
        'cpu_usage': CPU_USAGE,
        'memory_usage': MEMORY_USAGE
    })

def main():
    """
    Main function to start the application.
    """
    # Argument parsing
    parser = argparse.ArgumentParser(description="Traffic sniffer")
    parser.add_argument(
        '-i', '--interface', 
        type=str, 
        help='Network interface to sniff on'
    )
    
    args = parser.parse_args()
    
    # Automatically select the best interface if none is provided
    interface = args.interface if args.interface else get_best_interface()
    if not interface:
        raise RuntimeError("No active network interface with valid IPv4 or IPv6 addresses found.")
    
    logging.info(f"Using network interface: {interface}")
    
    # Start system usage monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor_system_usage, daemon=True)
    monitor_thread.start()

    # Start packet sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,), daemon=True)
    sniff_thread.start()

    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    main()
