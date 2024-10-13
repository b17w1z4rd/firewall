# Firewall

## Overview

This repository contains a custom-built firewall implemented in Go. It utilizes the `gopacket` library to capture and analyze network traffic, allowing for granular control over incoming and outgoing packets. The firewall enables users to define rules for blocking or allowing specific traffic, enhancing network security and monitoring.

## Features

- Packet capture and analysis using the `gopacket` library.
- Ability to block or allow packets based on user-defined rules.
- Works with multiple network interfaces.
- Simple command-line interface for easy usage.

## Requirements

- Go (1.16 or higher)
- `gopacket` library

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/b17w1z4rd/firewall.git
   cd firewall
## Usage
Identify the network interface you want to monitor. You can use the following command to list interfaces:
**ipconfig**(Windows)
2. Run the firewall tool specifying the network interface:
   go run firewall.go <interface_name>
