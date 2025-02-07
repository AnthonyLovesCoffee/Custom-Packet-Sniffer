from scapy.all import *
import time
import json
from collections import defaultdict, deque
import logging
from datetime import datetime
import argparse
import csv

class NetworkAnalyzer:
    def __init__(self, output_file=None, verbose=False, max_packets=100):
        self.start_time = time.time()
        self.packet_count = 0
        self.protocols = defaultdict(int)
        self.connections = defaultdict(int)
        self.suspicious_activity = []
        self.output_file = output_file
        self.verbose = verbose
        self.recent_packets = deque(maxlen=max_packets) 
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='network_analysis.log'
        )

    # analyse individual packets
    def analyse_packets(self, packet):
        try:
            if self.verbose:
                print("Received packet:", packet.summary())

            # check IP or IPv6
            if IP in packet:
                ip_layer = packet[IP]
            elif IPv6 in packet:
                ip_layer = packet[IPv6]
            else:
                if self.verbose:
                    print("Packet has no IP layer")
                return

            self.packet_count += 1
            protocol = ip_layer.proto
            
            if protocol in self.protocols:
                self.protocols[protocol] += 1
            else:
                self.protocols[protocol] = 1

            # getting port information
            src_port = dst_port = None
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # create connection key
            connection = f"{ip_layer.src}:{src_port} -> {ip_layer.dst}:{dst_port}"
            if connection in self.connections:
                self.connections[connection] += 1
            else:
                self.connections[connection] = 1

            packet_info = {
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': protocol,
                'timestamp': time.time()
            }
            self.recent_packets.append(packet_info)

            if self.verbose:
                print(f"Processed packet - Source: {ip_layer.src}:{src_port}, "
                      f"Dest: {ip_layer.dst}:{dst_port}, Protocol: {protocol}")

        except Exception as e:
            if self.verbose:
                print(f"Error processing packet: {e}")

    def get_recent_packets(self):
        return list(self.recent_packets)

    # analyse ethernet layer
    def _analyse_ethernet(self, packet):
        eth = packet[Ether]
        if self.verbose:
            print(f"\nEthernet Frame:")
            print(f"Source MAC: {eth.src}")
            print(f"Destination MAC: {eth.dst}")
            print(f"Protocol: {eth.type}")

    # analyse IP layer
    def _analyse_ip(self, packet):
        ip = packet[IP]
        self.protocols[ip.proto] += 1
        connection = f"{ip.src} → {ip.dst}"
        self.connections[connection] += 1

    # analyse TCP layer
    def _analyse_tcp(self, packet):
        """Analyzes TCP layer information and detects common services"""
        tcp = packet[TCP]
        # common services
        services = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            3306: 'MySQL',
            53: 'DNS'
        }
        if tcp.dport in services:
            logging.info(f"Detected {services[tcp.dport]} traffic")

    # generate statistics and save to JSON
    def _generate_statistics(self):
        stats = {
            'duration': time.time() - self.start_time,
            'total_packets': self.packet_count,
            'protocols': dict(self.protocols),
            'top_connections': dict(sorted(
                self.connections.items(), 
                key=lambda x: x[1], 
                reverse=True)[:10]),
        }
        
        with open('network_stats.json', 'w') as f:
            json.dump(stats, f, indent=4)
        
        if self.output_file:
            self._write_to_csv()

    def _write_to_csv(self):
        with open(self.output_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now(),
                self.packet_count,
                len(self.protocols),
            ])

    # current statistics for API
    def get_current_stats(self):
        return {
            'duration': time.time() - self.start_time,
            'total_packets': self.packet_count,
            'protocols': dict(self.protocols),
            'top_connections': dict(sorted(
                self.connections.items(), 
                key=lambda x: x[1], 
                reverse=True)[:10]),
        }

def main():
    parser = argparse.ArgumentParser(description='Advanced Network Traffic Analyzer')
    parser.add_argument('-o', '--output', help='Output CSV file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-t', '--time', type=int, help='Capture duration in seconds')
    args = parser.parse_args()

    try:
        analyzer = NetworkAnalyzer(args.output, args.verbose)
        print("Starting packet capture... Press Ctrl+C to stop")
        
        # start packet capture with time limit if specified
        if args.time:
            sniff(prn=analyzer.analyse_packets, store=False, timeout=args.time)
        else:
            sniff(prn=analyzer.analyse_packets, store=False)
            
    except KeyboardInterrupt:
        print("\nPacket capture stopped")
        # generate final report
        analyzer._generate_statistics()
        print(f"Full analysis saved to network_stats.json")
        if args.output:
            print(f"CSV data saved to {args.output}")

if __name__ == "__main__":
    main()