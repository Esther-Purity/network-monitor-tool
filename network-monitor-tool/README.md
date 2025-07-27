# Network Monitor Tool

A simple Python tool to capture and analyze network packets in real time.

## Features

- Captures packets using Scapy
- Displays IP addresses, protocols, and ports
- Logs all captured data to a file

## Requirements

- Python 3.7+
- Scapy

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
sudo python network_monitor.py
```

> ❗ Requires root privileges to capture packets on most systems

## Output

Captured packets will be saved in `packet_log.txt`.

## License

MIT