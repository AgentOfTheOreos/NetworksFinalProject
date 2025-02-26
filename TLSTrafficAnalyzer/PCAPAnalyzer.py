import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict
import numpy as np
import os
import re


def analyze_headers(packet):
    """
    Analyzes all relevant header fields from a packet
    """
    headers = {
        'ip': defaultdict(int),
        'tcp': defaultdict(int),
        'tls': defaultdict(int)
    }

    # A. IP Header Fields
    if hasattr(packet, 'ip'):
        headers['ip'].update({
            'version': packet.ip.version,
            'hdr_len': packet.ip.hdr_len,
            'dsfield': packet.ip.dsfield,
            'len': packet.ip.len,
            'id': packet.ip.id,
            'flags': packet.ip.flags,
            'frag_offset': packet.ip.frag_offset,
            'ttl': packet.ip.ttl,
            'proto': packet.ip.proto,
            'checksum': packet.ip.checksum,
            'src': packet.ip.src,
            'dst': packet.ip.dst
        })

    # B. TCP Header Fields
    if hasattr(packet, 'tcp'):
        headers['tcp'].update({
            'srcport': packet.tcp.srcport,
            'dstport': packet.tcp.dstport,
            'seq': packet.tcp.seq,
            'ack': packet.tcp.ack,
            'hdr_len': packet.tcp.hdr_len,
            'flags': packet.tcp.flags,
            'window_size': packet.tcp.window_size,
            'checksum': packet.tcp.checksum,
            'urgent_pointer': packet.tcp.urgent_pointer
        })

        # Additional TCP flags
        if hasattr(packet.tcp, 'flags_syn'): headers['tcp']['syn'] = packet.tcp.flags_syn
        if hasattr(packet.tcp, 'flags_ack'): headers['tcp']['ack_flag'] = packet.tcp.flags_ack
        if hasattr(packet.tcp, 'flags_fin'): headers['tcp']['fin'] = packet.tcp.flags_fin
        if hasattr(packet.tcp, 'flags_rst'): headers['tcp']['rst'] = packet.tcp.flags_rst
        if hasattr(packet.tcp, 'flags_push'): headers['tcp']['psh'] = packet.tcp.flags_push

    # C. TLS Header Fields
    if hasattr(packet, 'tls'):
        headers['tls'].update({
            'record_content_type': getattr(packet.tls, 'record_content_type', ''),
            'record_version': getattr(packet.tls, 'record_version', ''),
            'record_length': getattr(packet.tls, 'record_length', ''),
            'handshake_type': getattr(packet.tls, 'handshake_type', ''),
            'handshake_version': getattr(packet.tls, 'handshake_version', ''),
            'ciphersuite': getattr(packet.tls, 'handshake_ciphersuite', '')
        })

    return headers


def analyze_pcap(file_path, app_name):
    """
    Analyzes PCAP files with comprehensive header field coverage
    """
    try:
        cap = pyshark.FileCapture(file_path)

        metrics = {
            'packet_sizes': [],  # D. Packet Sizes
            'ip_headers': [],  # A. IP Headers
            'tcp_headers': [],  # B. TCP Headers
            'tls_headers': [],  # C. TLS Headers
            'timestamps': [],
            'protocols': defaultdict(int)
        }

        for packet in cap:
            # D. Packet Sizes
            metrics['packet_sizes'].append(int(packet.length))
            metrics['timestamps'].append(float(packet.sniff_timestamp))

            # Analyze headers
            headers = analyze_headers(packet)

            # Store header information
            if headers['ip']: metrics['ip_headers'].append(headers['ip'])
            if headers['tcp']: metrics['tcp_headers'].append(headers['tcp'])
            if headers['tls']: metrics['tls_headers'].append(headers['tls'])

            # Track protocols
            if hasattr(packet, 'highest_layer'):
                metrics['protocols'][packet.highest_layer] += 1

        cap.close()
        return metrics

    except Exception as e:
        print(f"Error analyzing {file_path}: {str(e)}")
        return None


def create_header_analysis_visualizations(app_metrics, output_dir):
    """
    Create visualizations for header analysis
    """
    os.makedirs(output_dir, exist_ok=True)

    for app_name, metrics in app_metrics.items():
        # D. Packet Size Distribution
        plt.figure(figsize=(10, 6))
        plt.hist(metrics['packet_sizes'], bins=50, alpha=0.7)
        plt.title(f'Packet Size Distribution - {app_name}')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.savefig(os.path.join(output_dir, f'{app_name}_packet_sizes.png'))
        plt.close()

        # A. IP Header Analysis
        if metrics['ip_headers']:
            ip_df = pd.DataFrame(metrics['ip_headers'])
            ip_ttl_dist = ip_df['ttl'].value_counts()
            plt.figure(figsize=(10, 6))
            ip_ttl_dist.plot(kind='bar')
            plt.title(f'IP TTL Distribution - {app_name}')
            plt.xlabel('TTL Value')
            plt.ylabel('Count')
            plt.savefig(os.path.join(output_dir, f'{app_name}_ip_ttl.png'))
            plt.close()

        # B. TCP Header Analysis
        if metrics['tcp_headers']:
            tcp_df = pd.DataFrame(metrics['tcp_headers'])
            plt.figure(figsize=(10, 6))
            tcp_df['window_size'].hist(bins=50)
            plt.title(f'TCP Window Size Distribution - {app_name}')
            plt.xlabel('Window Size')
            plt.ylabel('Frequency')
            plt.savefig(os.path.join(output_dir, f'{app_name}_tcp_window.png'))
            plt.close()

        # C. TLS Header Analysis
        if metrics['tls_headers']:
            tls_df = pd.DataFrame(metrics['tls_headers'])
            if 'record_version' in tls_df.columns:
                version_dist = tls_df['record_version'].value_counts()
                plt.figure(figsize=(10, 6))
                version_dist.plot(kind='bar')
                plt.title(f'TLS Version Distribution - {app_name}')
                plt.xlabel('TLS Version')
                plt.ylabel('Count')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(os.path.join(output_dir, f'{app_name}_tls_versions.png'))
                plt.close()


def generate_header_statistics(app_metrics):
    """
    Generate comprehensive statistics about header fields
    """
    stats = {}
    for app_name, metrics in app_metrics.items():
        stats[app_name] = {
            'total_packets': len(metrics['packet_sizes']),
            'avg_packet_size': np.mean(metrics['packet_sizes']),
            'ip_packets': len(metrics['ip_headers']),
            'tcp_packets': len(metrics['tcp_headers']),
            'tls_packets': len(metrics['tls_headers']),
            'protocols': dict(metrics['protocols'])
        }

    return pd.DataFrame(stats).T


def main():
    # Get pcap files from directory
    pcap_dir = "PCAPNGs"
    output_dir = "header_analysis_results"

    if not os.path.exists(pcap_dir):
        os.makedirs(pcap_dir)
        print(f"Created directory: {pcap_dir}")
        return

    pcap_files = {
        re.sub(r'[\d_-]+\.pcapng$', '', f, flags=re.IGNORECASE).replace('_', ' ').strip().title():
            os.path.join(pcap_dir, f)
        for f in os.listdir(pcap_dir) if f.lower().endswith('.pcapng')
    }

    if not pcap_files:
        print(f"No .pcapng files found in {pcap_dir}")
        return

    # Analyze each application's traffic
    app_metrics = {}
    for app_name, file_path in pcap_files.items():
        print(f"Analyzing {app_name}...")
        metrics = analyze_pcap(file_path, app_name)
        if metrics:
            app_metrics[app_name] = metrics

    # Create visualizations and statistics
    create_header_analysis_visualizations(app_metrics, output_dir)
    stats_df = generate_header_statistics(app_metrics)
    stats_df.to_csv(os.path.join(output_dir, 'header_statistics.csv'))
    print("\nHeader Analysis Statistics:")
    print(stats_df)


if __name__ == "__main__":
    main()