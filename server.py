from flask import Flask, request, jsonify
import threading
import pyshark

app = Flask(__name__)

captured_packets = []

"""
def packet_handler(pkt):
    try:
        info = {
            "protocol": pkt.highest_layer,
            "src": pkt.ip.src if hasattr(pkt, 'ip') else None,
            "dst": pkt.ip.dst if hasattr(pkt, 'ip') else None,
            "length": pkt.length if hasattr(pkt, 'length') else None,
        }
        captured_packets.append(info)
        print(f"[+] {info}")
    except Exception as e:
        print("Error parsing packet:", e)
"""

def packet_handler(pkt):
    try:
        # IP Layer
        src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
        dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None
        ttl = int(pkt.ip.ttl) if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'ttl') else None

        # TCP/UDP Layer
        src_port = None
        dst_port = None
        flags = None
        if hasattr(pkt, 'tcp'):
            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
            flags = pkt.tcp.flags
        elif hasattr(pkt, 'udp'):
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)

        # MAC addresses (Ethernet Layer)
        src_mac = pkt.eth.src if hasattr(pkt, 'eth') else None
        dst_mac = pkt.eth.dst if hasattr(pkt, 'eth') else None

        # Protocol and length
        info = {
            "protocol": pkt.highest_layer,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": flags,
            "ttl": ttl,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "length": int(pkt.length) if hasattr(pkt, 'length') else None,
        }

        captured_packets.append(info)
        print(f"[+] {info}")

    except Exception as e:
        print("Error parsing packet:", e)

def start_sniffing(interface="eth0"):
    capture = pyshark.LiveCapture(interface=interface)
    capture.apply_on_packets(packet_handler, timeout=1000)


@app.route('/')
def index():
    return jsonify({"status": "running", "packets_seen": len(captured_packets)})

@app.route('/packets')
def get_packets():
    print(f"Fprtmote {jsonify(captured_packets[-50:])}")
    return jsonify(captured_packets[-50:])  # Return the last 50 packets

if __name__ == '__main__':
    # Run packet capture in a background thread
    sniff_thread = threading.Thread(target=start_sniffing, args=("eth0",), daemon=True)
    sniff_thread.start()
    
    # Start Flask
    app.run(host='0.0.0.0', port=5000)
