import threading
import csv
import logging
import pyshark
import io
import psutil
import time
from flask import Flask, jsonify, Response, make_response
from flask_cors import CORS
from collections import defaultdict

# Flask app initialization
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global constants and variables
TRAFFIC_DATA = []
CPU_USAGE = 0
MEMORY_USAGE = 0

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
    protocol = 2054  # ARP protocol number
    arp_src_ip = pkt.arp.src_proto_ipv4
    arp_dst_ip = pkt.arp.dst_proto_ipv4
    arp_src_mac = pkt.arp.src_hw_mac
    arp_dst_mac = pkt.arp.dst_hw_mac
    arp_op_code = int(pkt.arp.opcode)

    arp_op = "ARP Request" if arp_op_code == 1 else "ARP Reply" if arp_op_code == 2 else f"ARP Opcode {arp_op_code}"

    detailed_info = (f"{arp_op} from {arp_src_ip} ({arp_src_mac}) to {arp_dst_ip} ({arp_dst_mac}) | "
                     f"Hardware Type: {pkt.arp.hw_type}, Protocol Type: {pkt.arp.proto_type}, "
                     f"Hardware Size: {pkt.arp.hw_size}, Protocol Size: {pkt.arp.proto_size}")

    return {
        "No.": len(TRAFFIC_DATA) + 1,
        "Time": pkt.sniff_time.isoformat(),
        "Source": arp_src_ip,
        "Destination": arp_dst_ip,
        "Protocol": "ARP",
        "Length": pkt.length,
        "Info": arp_op,
        "Detailed Info": detailed_info
    }


def process_ip_packet(pkt, protocol, ip_src, ip_dst):
    """
    Processes IP packets and returns a dictionary containing packet details.
    """
    src_port, dst_port, layer, info = None, None, None, []

    # Extract transport layer information
    if hasattr(pkt, 'tcp'):
        layer = "TCP"
        src_port = int(pkt.tcp.srcport)
        dst_port = int(pkt.tcp.dstport)
        info.extend([
            f"Flags: {pkt.tcp.flags}",
            f"Window Size: {pkt.tcp.window_size}",
            f"Sequence Number: {pkt.tcp.seq}",
            f"Acknowledgment Number: {pkt.tcp.ack}",
            f"Options: {pkt.tcp.options}" if hasattr(pkt.tcp, 'options') else ""
        ])

    elif hasattr(pkt, 'udp'):
        layer = "UDP"
        src_port = int(pkt.udp.srcport)
        dst_port = int(pkt.udp.dstport)
        info.append(f"Length: {pkt.udp.length}")

    if hasattr(pkt, 'http'):
        http_info = f"HTTP {pkt.http.request_method} {pkt.http.host}{pkt.http.request_uri}"
        info.append(http_info)

    if hasattr(pkt, 'dns'):
        if pkt.dns.qry_name:
            dns_info = f"DNS Query: {pkt.dns.qry_name} | Type: {pkt.dns.qry_type}"
            info.append(dns_info)
        if hasattr(pkt.dns, 'a'):
            dns_response_info = f"DNS Response: {pkt.dns.a}"
            info.append(dns_response_info)
        if hasattr(pkt.dns, 'aaaa'):
            dns_response_info_aaaa = f"DNS Response (AAAA): {pkt.dns.aaaa}"
            info.append(dns_response_info_aaaa)
        if hasattr(pkt.dns, 'cname'):
            dns_cname_info = f"CNAME: {pkt.dns.cname}"
            info.append(dns_cname_info)
        if hasattr(pkt.dns, 'qry_name') and hasattr(pkt.dns, 'qry_type'):
            for i in range(int(pkt.dns.qry_name.count(' ')) + 1):
                qry_name = getattr(pkt.dns, f'qry_name_{i}', pkt.dns.qry_name)
                qry_type = getattr(pkt.dns, f'qry_type_{i}', pkt.dns.qry_type)
                info.append(f"Standard query 0x{pkt.dns.id} {qry_name}, \"QU\" question {qry_type}")

    protocol_name = get_protocol_name(protocol, src_port, dst_port, layer)

    detailed_info = f"{protocol_name} packet from {ip_src}:{src_port} to {ip_dst}:{dst_port}"

    return {
        "No.": len(TRAFFIC_DATA) + 1,
        "Time": pkt.sniff_time.isoformat(),
        "Source": ip_src,
        "Destination": ip_dst,
        "Protocol": protocol_name,
        "Length": pkt.length,
        "Info": " | ".join(info),
        "Detailed Info": detailed_info
    }


def packet_callback(pkt):
    """
    Callback function that processes each packet captured by pyshark.
    """
    try:
        ip_src, ip_dst, protocol = None, None, None

        # Handle ARP packets
        if hasattr(pkt, 'arp'):
            packet_info = process_arp_packet(pkt)
            TRAFFIC_DATA.append(packet_info)
            return

        # Handle IP packets
        if hasattr(pkt, 'ip'):
            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
            protocol = int(pkt.ip.proto)
        elif hasattr(pkt, 'ipv6'):
            ip_src = pkt.ipv6.src
            ip_dst = pkt.ipv6.dst
            protocol = int(pkt.ipv6.nxt)  # Next header field as protocol

        if ip_src and ip_dst and protocol is not None:
            packet_info = process_ip_packet(pkt, protocol, ip_src, ip_dst)
            TRAFFIC_DATA.append(packet_info)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")


def start_sniffing(interface):
    """
    Starts the packet capturing process on the specified network interface.
    """
    try:
        capture = pyshark.LiveCapture(interface=interface)
        capture.apply_on_packets(packet_callback)
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
    return jsonify(TRAFFIC_DATA[-500:])  # Send the last 500 entries


@app.route('/export/csv', methods=['GET'])
def export_csv():
    """
    Endpoint to export captured traffic data as a CSV file.
    """
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Detailed Info"])
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
    # Start system usage monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor_system_usage, daemon=True)
    monitor_thread.start()

    # Start packet sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, args=("en0",), daemon=True)  # Replace "en0" with your network interface
    sniff_thread.start()

    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == '__main__':
    main()
