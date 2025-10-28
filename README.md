# Python Packet Sniffer



This is a command-line packet sniffing and analysis tool built with Python and Scapy. It's an educational project for cybersecurity students to understand network fundamentals.



## Features

* Captures live network traffic on a specified interface.

* Parses and displays L3 (IP) and L4 (TCP/UDP) information.

* Detects and displays clear-text HTTP request details (Host, Path, Method).

* Includes a basic keyword scanner for clear-text payloads (e.g., "user", "pass").



## Requirements

* Python 3.x

* Scapy

* Root / Administrator privileges (for packet capture)



## Installation

1.  Clone the repository:

```bash

git clone \[https://github.com/KareesaRao/Packet-Sniffer.git](https://github.com/KareesaRao/Packet-Sniffer.git)

cd Packet-Sniffer

```

2.  Create and activate a virtual environment:

```bash

# On Windows

python -m venv venv

.\\venv\\Scripts\\activate

```

3.  Install dependencies:

```bash

pip install -r requirements.txt

```



## Usage

1.  Find your active network interface name (e.g., 'eth0', 'WiFi').

2.  Update the `INTERFACE\_TO\_SNIFF` variable in `sniffer.py`.

3.  Run the script with elevated privileges:

```bash

# On Windows (in an Admin terminal)

python sniffer.py

```

