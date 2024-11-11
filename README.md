# Network_Packet_Sniffer

This project is a packet sniffer application built in C++ using the Npcap library and Winsock2 on Windows. It allows users to capture network packets, parse Ethernet, IP, TCP, and UDP headers, and display packet information such as MAC addresses, IP addresses, and port numbers.

## Table of Contents
1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Building the Project](#building-the-project)
5. [Running the Packet Sniffer](#running-the-packet-sniffer)
6. [Usage](#usage)
7. [Troubleshooting](#troubleshooting)
8. [License](#license)

---

## Features
- Captures live network packets on a specified interface.
- Parses and displays Ethernet, IP, TCP, and UDP header information.
- Supports Windows with Npcap as the packet capture library.
- Easy to extend for additional protocol support.

## Requirements
1. **Operating System**: Windows
2. **Libraries**:
   - **Npcap**: A packet capture library compatible with Windows, available from the [Npcap website](https://nmap.org/npcap/).
   - **Winsock2**: Standard library for Windows network programming.
3. **Development Environment**:
   - **Microsoft Visual Studio** (recommended for Windows development).

## Installation

### Step 1: Install Npcap
1. Download the latest version of Npcap from the official [Npcap download page](https://nmap.org/npcap/).
2. Run the installer with administrative privileges.
3. During installation, ensure you select:
   - **Install Npcap in WinPcap API-compatible Mode** (optional, but recommended for compatibility).
   - **Support raw 802.11 traffic (and monitor mode) for WiFi adapters** (optional, if you need to capture WiFi packets).
4. Complete the installation and verify that Npcap is installed.

### Step 2: Clone the Repository
Clone this GitHub repository to your local machine:
```bash
git clone https://github.com/yourusername/PacketSniffer.git
cd PacketSniffer
