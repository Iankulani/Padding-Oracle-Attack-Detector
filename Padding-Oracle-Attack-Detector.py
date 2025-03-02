# -*- coding: utf-8 -*-
"""
Created on Sun Mar 2 6:10:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Padding Oracle Attack Detector")
print(Fore.GREEN+font)

import scapy.all as scapy
import time
import re

# Dictionary to track error messages related to padding
padding_error_count = {}

def packet_callback(packet):
    # Check if the packet contains an IP layer and TLS/SSL layer
    if packet.haslayer(scapy.IP):
        # Extract source and destination IP addresses
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        # Check for SSL/TLS layer, which might be using CBC mode encryption
        if packet.haslayer(scapy.TLS):
            tls_record = packet[scapy.TLS]
            
            # Look for TLS alert messages that indicate padding errors
            if hasattr(tls_record, 'alert') and 'alert_description' in tls_record.alert:
                alert_desc = tls_record.alert['alert_description']
                
                # A padding error might be shown as 'bad_record_mac' or other TLS alert codes
                if alert_desc in ['bad_record_mac', 'decryption_failed', 'record_overflow']:
                    print(f"Padding error detected: {alert_desc} from {src_ip} to {dst_ip}")
                    
                    # Track the number of padding errors per source IP
                    if src_ip not in padding_error_count:
                        padding_error_count[src_ip] = 0
                    padding_error_count[src_ip] += 1

                    # If multiple padding errors from the same IP, it could be a sign of an attack
                    if padding_error_count[src_ip] > 5:
                        print(f"Potential Padding Oracle Attack detected from {src_ip}")
                        return

def detect_padding_oracle_attack(ip_address):
    print(f"Monitoring traffic to/from {ip_address} for potential Padding Oracle Attack...")
    
    start_time = time.time()
    while time.time() - start_time < 60:  # Monitor for 1 minute
        time.sleep(1)

    # If no attack is detected within the last minute
    print("No Padding Oracle Attack detected within the last minute of monitoring.")

def start_monitoring():
    # Prompt the user to input the IP address to monitor
    ip_address = input("Enter the IP address to monitor for Padding Oracle Attack:")
    
    # Start sniffing for packets to/from the given IP address
    print(f"Starting packet capture for IP: {ip_address}")
    scapy.sniff(prn=packet_callback, filter=f"ip host {ip_address}", store=0, timeout=60)

    # After capturing packets, analyze for potential Padding Oracle Attack
    detect_padding_oracle_attack(ip_address)

if __name__ == "__main__":
    start_monitoring()
