from flask import Flask, jsonify, Response, make_response
from flask_cors import CORS
import threading
import csv
import logging
import pyshark
import io
import psutil
import time
from collections import defaultdict

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

traffic_data = []  # List to store captured packet data

# Known protocol mappings
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6"
}

# Application layer protocol mapping based on port numbers
APPLICATION_PROTOCOLS = {
    (5353, "UDP"): "mDNS",
    (80, "TCP"): "HTTP",
    (443, "TCP"): "HTTPS"
}

# Global variables to store CPU and memory usage
cpu_usage = 0
memory_usage = 0

# Set up logging to capture errors and information
logging.basicConfig(level=logging.INFO)

def get_protocol_name(protocol_number, src_port=None, dst_port=None, layer="TCP"):
    """
    Returns the protocol name based on the protocol number and optional port numbers.
    """
    if protocol_number in PROTOCOLS:
        if src_port and dst_port:
            return APPLICATION_PROTOCOLS.get((src_port, layer), APPLICATION_PROTOCOLS.get((dst_port, layer), PROTOCOLS[protocol_number]))
        return PROTOCOLS[protocol_number]
    return f"Unknown ({protocol_number})"

def packet_callback(pkt):
    """
    Callback function that processes each packet captured by pyshark.
    """
    try:
        ip_src = ip_dst = protocol = None
        info = []

        if hasattr(pkt, 'ip'):
            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
            protocol = int(pkt.ip.proto)
        elif hasattr(pkt, 'ipv6'):
            ip_src = pkt.ipv6.src
            ip_dst = pkt.ipv6.dst
            protocol = int(pkt.ipv6.nxt)  # Next header field as protocol

        if ip_src and ip_dst and protocol is not None:
            src_port = dst_port = None
            layer = None

            if hasattr(pkt, 'tcp'):
                layer = "TCP"
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
                info.append(f"Flags: {pkt.tcp.flags}")
                info.append(f"Window Size: {pkt.tcp.window_size}")
                info.append(f"Sequence Number: {pkt.tcp.seq}")
                info.append(f"Acknowledgment Number: {pkt.tcp.ack}")
                if hasattr(pkt.tcp, 'options'):
                    info.append(f"Options: {pkt.tcp.options}")

            elif hasattr(pkt, 'udp'):
                layer = "UDP"
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)
                info.append(f"Length: {pkt.udp.length}")

            if hasattr(pkt, 'http'):
                http_info = f"HTTP {pkt.http.request_method} {pkt.http.host}{pkt.http.request_uri}"
                info.append(http_info)

            if hasattr(pkt, 'dns'):
                dns_info = f"DNS Query: {pkt.dns.qry_name} Type: {pkt.dns.qry_type}"
                info.append(dns_info)

            protocol_name = get_protocol_name(protocol, src_port, dst_port, layer)

            detailed_info = f"{protocol_name} packet from {ip_src}:{src_port} to {ip_dst}:{dst_port}"

            packet_info = {
                "No.": len(traffic_data) + 1,
                "Time": pkt.sniff_time.isoformat(),
                "Source": ip_src,
                "Destination": ip_dst,
                "Protocol": protocol_name,
                "Length": pkt.length,
                "Info": " | ".join(info),
                "Detailed Info": detailed_info
            }

            traffic_data.append(packet_info)
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def start_sniffing(interface):
    """
    Starts the packet capturing process on the specified network interface.
    """
    capture = pyshark.LiveCapture(interface=interface)
    capture.apply_on_packets(packet_callback)

def monitor_system_usage():
    global cpu_usage, memory_usage
    while True:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        memory_usage = memory_info.percent
        time.sleep(5)  # Update every 5 seconds

@app.route('/traffic', methods=['GET'])
def get_traffic():
    """
    Endpoint to retrieve captured traffic data in JSON format.
    """
    return jsonify(traffic_data)

@app.route('/export/csv', methods=['GET'])
def export_csv():
    """
    Endpoint to export captured traffic data as a CSV file.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Detailed Info"])
    for packet in traffic_data:
        writer.writerow([packet["No."], packet["Time"], packet["Source"], packet["Destination"], packet["Protocol"], packet["Length"], packet["Info"], packet["Detailed Info"]])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=traffic_data.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/system-usage', methods=['GET'])
def get_system_usage():
    """
    Endpoint to retrieve current CPU and memory usage.
    """
    return jsonify({
        'cpu_usage': cpu_usage,
        'memory_usage': memory_usage
    })

if __name__ == '__main__':
    # Start system monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor_system_usage)
    monitor_thread.daemon = True
    monitor_thread.start()

    # Start packet sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, args=("en0",))  # Replace "en0" with your network interface
    sniff_thread.start()

    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
