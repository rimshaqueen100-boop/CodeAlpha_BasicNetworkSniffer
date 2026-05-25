# CodeAlpha: Basic Network Sniffer

## Description
This is a basic network packet sniffer developed in Python using the Scapy library as part of my CodeAlpha Cybersecurity Internship. The tool captures real-time network traffic and extracts vital information such as Source IP addresses, Destination IP addresses, and protocols (TCP/UDP/ICMP).

## Features
- Real-time packet capture on the active network interface.
- Protocol identification (TCP, UDP, ICMP).
- Clean console output showing traffic flow direction.

## Prerequisites
- Python 3.x
- Scapy library (`pip install scapy`)
- Npcap driver (for Windows packet capture support)

## How to Run
1. Open Command Prompt as an **Administrator**.
2. Navigate to the project directory:
   ```cmd
   cd "C:\Users\UMAIR\OneDrive\Desktop\CodeAlpha_BasicNetworkSniffer"