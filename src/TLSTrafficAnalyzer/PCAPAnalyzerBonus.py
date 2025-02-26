#!/usr/bin/env python3
"""
Step 3: Attacker Simulation Script

This script simulates an attacker who observes network traffic and extracts:
  - Packet timestamp
  - Packet size (in bytes)
  - A hash of the 4-tuple (src IP, dst IP, src port, dst port) if available

It then creates plots to help analyze whether the observed characteristics can be used
to infer which apps/sites were accessed.
"""
import glob
import os
import hashlib
import re

import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP


def compute_flow_hash(src, sport, dst, dport):
    """
    Compute a hash for a TCP flow given the 4-tuple.
    """
    flow_str = f"{src}:{sport}-{dst}:{dport}"
    return hashlib.sha256(flow_str.encode()).hexdigest()


def extract_packet_info(pcap_file):
    """
    Read the pcap file and extract the timestamp, packet size, and flow hash
    from each packet.
    """
    print(f"Reading packets from: {pcap_file}")
    packets = rdpcap(pcap_file)
    data = []

    for pkt in packets:
        try:
            # Focus on IP packets only
            if IP in pkt:
                ts = pkt.time
                size = len(pkt)
                flow_hash = None
                if TCP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    flow_hash = compute_flow_hash(src_ip, src_port, dst_ip, dst_port)
                data.append({
                    "timestamp": ts,
                    "packet_size": size,
                    "flow_hash": flow_hash
                })
        except Exception as e:
            print("Error processing packet:", e)
    df = pd.DataFrame(data)
    return df


def plot_packet_sizes_over_time(df, title_suffix=""):
    """
    Create a scatter plot of packet sizes over time.
    """
    plt.figure(figsize=(12, 6))
    plt.scatter(df['timestamp'], df['packet_size'], s=1, alpha=0.6)
    plt.xlabel('Timestamp')
    plt.ylabel('Packet Size (bytes)')
    plt.title(f'Packet Size vs. Time {title_suffix}')
    plt.grid(True)
    plt.show()


def plot_packet_size_distribution(df, title_suffix=""):
    """
    Create a histogram of packet sizes.
    """
    plt.figure(figsize=(8, 6))
    plt.hist(df['packet_size'], bins=50, color='skyblue', edgecolor='black')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.title(f'Packet Size Distribution {title_suffix}')
    plt.grid(True)
    plt.show()


def analyze_flow_patterns(df):
    """
    Group packets by flow hash to analyze flow-based patterns.
    """
    flows = df.dropna(subset=['flow_hash']).groupby('flow_hash').agg({
        'packet_size': ['mean', 'count'],
        'timestamp': ['min', 'max']
    })
    flows.columns = ['avg_packet_size', 'packet_count', 'flow_start', 'flow_end']
    flows['duration'] = flows['flow_end'] - flows['flow_start']

    print("Flow Analysis (first few flows):")
    print(flows.head())

    # Scatter plot: Packet count vs. average packet size per flow
    plt.figure(figsize=(10, 6))
    plt.scatter(flows['packet_count'], flows['avg_packet_size'], alpha=0.7)
    plt.xlabel('Packet Count per Flow')
    plt.ylabel('Average Packet Size (bytes)')
    plt.title('Flow Characteristics: Packet Count vs. Average Packet Size')
    plt.grid(True)
    plt.show()


def main():
    # Directory containing the PCAPNG files
    pcap_dir = "PCAPNGs/Bonus"

    if not os.path.isdir(pcap_dir):
        print(f"Directory '{pcap_dir}' not found in the project directory.")
        return

    # Find all .pcapng files in the directory
    pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcapng"))
    if not pcap_files:
        print(f"No .pcapng files found in '{pcap_dir}'.")
        return

    # Process each pcapng file individually
    for pcap_file in pcap_files:
        print(f"\nProcessing file: {pcap_file}")
        df = extract_packet_info(pcap_file)
        print(f"Extracted {len(df)} packets from {pcap_file}.")

        # Save extracted data to a CSV file
        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        csv_filename = f"extracted_packet_info_{base_name}.csv"
        df.to_csv(csv_filename, index=False)
        print(f"Extracted data saved to '{csv_filename}'.")

        # Generate plots with a title suffix
        title_suffix = f"({base_name})"
        plot_packet_sizes_over_time(df, title_suffix=title_suffix)
        plot_packet_size_distribution(df, title_suffix=title_suffix)
        analyze_flow_patterns(df)


if __name__ == "__main__":
    main()
