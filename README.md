# Scanio - Network Scanner

**Scanio** is a high-performance, multithreaded port scanner written in C++. It supports both TCP Connect and SYN scanning modes, features ICMP host detection, optional service/banner grabbing, and provides real-time scan progress with estimated time remaining. It is built for speed, efficiency, and flexibility, making it a powerful tool for network reconnaissance.

---

## Features

- Scan specific ports, top common ports, or all 65535 ports
- High-speed multithreaded architecture using a custom thread pool
- ICMP ping to check if a host is online before scanning
- Optional banner grabbing to identify services on open ports
- Live progress tracking with estimated time of arrival (ETA)
- Raw socket support for SYN scanning (requires root access)

---

## Build Instructions

### Requirements

- C++17 or later
- Linux (raw sockets and ICMP scanning rely on POSIX features)

### Compilation

```bash
g++ -std=c++17 main.cpp -o scanio -lpthread
```

---

### Options

```
# Target IP address (required)
-i, --ip

# Ports to scan (e.g., 80, 20-25, 21,22,23)
-p, --ports

#Scan top N common ports (e.g., -Tp 100)
-Tp, --top-ports

# Scan all 65535 TCP ports
-Ap, --all-ports

# Use TCP Connect scan (default is SYN scan)
-Ts, --tcp-scan

# Enable banner grabbing for service detection
-S, --service

# Timeout for port probes in seconds (default: 3)
-d, --delay

# Number of threads to use for scanning (default: 100)
-Th, --threads
```

---

### Example Usage

```
# Scan top 100 common ports on 192.168.1.1 using 200 threads
./scanio -i 192.168.1.1 -Tp 100 -Th 200

# Full TCP SYN scan of all 65535 ports (requires root)
sudo ./scanio -i 192.168.1.1 -Ap

# TCP Connect scan with banner grabbing on selected ports
./scanio -i 192.168.1.1 -p 21,22,80 -Ts -S

# Scan a custom port range with default threads and SYN scan
./scanio -i 192.168.1.1 -p 20-30
```

---

### Legal Disclaimer

Scanio is intended for educational and authorized security testing purposes only.
Do not use this tool on networks or systems you do not own or lack explicit permission to test. Unauthorized scanning can be illegal and unethical. The author takes no responsibility for any misuse.
