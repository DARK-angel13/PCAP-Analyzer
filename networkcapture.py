import pyshark
import dpkt
import socket
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score
import os

# Prompt user for file path
file_path = input("Enter the full path to your PCAP/PCAPNG file: ").strip()
if not os.path.exists(file_path):
    raise FileNotFoundError("File not found. Please check the path and try again.")

def get_ip(packet):
    try:
        return socket.inet_ntoa(packet)
    except ValueError:
        return 'Unknown'

def analyze_pcap(file_path):
    protocol_counter = Counter()
    ip_communication = Counter()
    port_scanning = defaultdict(set)
    total_bandwidth = 0
    packet_timestamps = []
    ip_bandwidth = defaultdict(int)
    features = []
    labels = []
    
    if file_path.endswith('.pcap'):
        with open(file_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            prev_timestamp = None
            for timestamp, buf in pcap:
                total_bandwidth += len(buf)
                packet_timestamps.append(timestamp)
                eth = dpkt.ethernet.Ethernet(buf)
                
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src_ip = get_ip(ip.src)
                    dst_ip = get_ip(ip.dst)
                    ip_bandwidth[src_ip] += len(buf)
                    ip_bandwidth[dst_ip] += len(buf)
                    protocol_counter[ip.p] += 1
                    ip_communication[(src_ip, dst_ip)] += 1

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        port_scanning[src_ip].add(tcp.dport)

                    if prev_timestamp is not None:
                        latency = timestamp - prev_timestamp
                    prev_timestamp = timestamp

                    features.append([len(buf), ip.p])
                    labels.append(1 if len(port_scanning[src_ip]) > 10 else 0)
    
    else:
        cap = pyshark.FileCapture(file_path)
        prev_timestamp = None
        for packet in cap:
            try:
                timestamp = float(packet.sniff_timestamp)
                total_bandwidth += int(packet.length)
                packet_timestamps.append(timestamp)
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.highest_layer
                
                ip_bandwidth[src_ip] += int(packet.length)
                ip_bandwidth[dst_ip] += int(packet.length)
                protocol_counter[protocol] += 1
                ip_communication[(src_ip, dst_ip)] += 1

                if hasattr(packet, 'tcp'):
                    port_scanning[src_ip].add(int(packet.tcp.dstport))

                if prev_timestamp is not None:
                    latency = timestamp - prev_timestamp
                prev_timestamp = timestamp

                features.append([int(packet.length), 6 if protocol == "TCP" else 17])
                labels.append(1 if len(port_scanning[src_ip]) > 10 else 0)
            except AttributeError:
                continue

    return protocol_counter, ip_communication, port_scanning, total_bandwidth, ip_bandwidth, packet_timestamps, features, labels

def detect_port_scanning(port_scanning):
    return {ip: ports for ip, ports in port_scanning.items() if len(ports) > 10}

def plot_graph(ip_bandwidth):
    ips, bandwidths = zip(*sorted(ip_bandwidth.items(), key=lambda x: x[1], reverse=True)[:10])
    plt.figure(figsize=(10,5))
    plt.bar(ips, bandwidths, color='skyblue')
    plt.xlabel('IP Address')
    plt.ylabel('Bandwidth Used (bytes)')
    plt.title('Top 10 IPs by Bandwidth')
    plt.xticks(rotation=45)
    plt.show()

def calculate_network_metrics(packet_timestamps):
    if len(packet_timestamps) < 2:
        return None, None, None, None, None

    time_intervals = np.diff(packet_timestamps)
    latency = np.mean(time_intervals)
    packet_loss = (1 - len(time_intervals) / len(packet_timestamps)) * 100
    throughput = len(packet_timestamps) / (packet_timestamps[-1] - packet_timestamps[0])
    jitter = np.std(time_intervals)
    utilization = (sum(time_intervals) / (packet_timestamps[-1] - packet_timestamps[0])) * 100

    return latency, packet_loss, throughput, jitter, utilization

def train_ml_model(features, labels):
    X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
    model = make_pipeline(StandardScaler(), RandomForestClassifier(n_estimators=100, random_state=42))
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"ML Model Accuracy: {accuracy * 100:.2f}%")
    return model

protocol_counter, ip_communication, port_scanning, total_bandwidth, ip_bandwidth, packet_timestamps, features, labels = analyze_pcap(file_path)

print(f"Total Bandwidth Used: {total_bandwidth} bytes")
print("Protocol Distribution:")
for proto, count in protocol_counter.items():
    print(f"{proto}: {count} packets")

print("Top IP Communications:")
for (src, dst), count in ip_communication.most_common(10):
    print(f"{src} -> {dst}: {count} packets")

potential_scanners = detect_port_scanning(port_scanning)
if potential_scanners:
    print("Potential Port Scanners Detected:")
    for ip, ports in potential_scanners.items():
        print(f"{ip} scanned {len(ports)} ports")
else:
    print("No significant port scanning detected.")

plot_graph(ip_bandwidth)
latency, packet_loss, throughput, jitter, utilization = calculate_network_metrics(packet_timestamps)
print(f"Latency: {latency:.4f} sec")
print(f"Packet Loss: {packet_loss:.2f}%")
print(f"Throughput: {throughput:.2f} packets/sec")
print(f"Jitter: {jitter:.4f} sec")
print(f"Network Utilization: {utilization:.2f}%")

train_ml_model(features, labels)
