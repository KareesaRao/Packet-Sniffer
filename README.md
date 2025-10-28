\# Python Packet Sniffer



This is a command-line packet sniffing and analysis tool built with Python and Scapy. It's an educational project for cybersecurity students to understand network fundamentals.



\## Features

\* Captures live network traffic on a specified interface.

\* Parses and displays L3 (IP) and L4 (TCP/UDP) information.

\* Detects and displays clear-text HTTP request details (Host, Path, Method).

\* Includes a basic keyword scanner for clear-text payloads (e.g., "user", "pass").



\## Requirements

\* Python 3.x

\* Scapy

\* Root / Administrator privileges (for packet capture)



\## Installation

1\.  Clone the repository:

&nbsp;   ```bash

&nbsp;   git clone \[https://github.com/KareesaRao/Packet-Sniffer.git](https://github.com/KareesaRao/Packet-Sniffer.git)

&nbsp;   cd Packet-Sniffer

&nbsp;   ```

2\.  Create and activate a virtual environment:

&nbsp;   ```bash

&nbsp;   # On Windows

&nbsp;   python -m venv venv

&nbsp;   .\\venv\\Scripts\\activate

&nbsp;   ```

3\.  Install dependencies:

&nbsp;   ```bash

&nbsp;   pip install -r requirements.txt

&nbsp;   ```



\## Usage

1\.  Find your active network interface name (e.g., 'eth0', 'WiFi').

2\.  Update the `INTERFACE\_TO\_SNIFF` variable in `sniffer.py`.

3\.  Run the script with elevated privileges:

&nbsp;   ```bash

&nbsp;   # On Windows (in an Admin terminal)

&nbsp;   python sniffer.py

&nbsp;   ```

