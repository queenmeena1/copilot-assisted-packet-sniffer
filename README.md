\# Copilot-Assisted Packet Sniffer



\## Project Description



This project is a Python packet sniffer built with Scapy for authorized educational and lab traffic. The purpose of the project is to demonstrate packet capture, packet decoding, DNS observation, and responsible handling of network information.



\## Learning Goals



\- Understand packet capture concepts including frames, IP, TCP/UDP, DNS, and HTTP.

\- Practice secure development with AI assistance.

\- Capture only authorized traffic.

\- Redact sensitive information before displaying or logging packet data.

\- Understand why packet sniffers are powerful and how defenders can detect misuse.



\## Ethical Use



This tool is intended only for:



\- My own computer and network traffic.

\- Loopback traffic.

\- Instructor-provided lab traffic.

\- Authorized educational environments.



Do not use this tool to capture other people's traffic, bypass operating system permissions, hide activity, maintain persistence, or collect information without authorization.



\## Requirements



\- Python 3.10+

\- Scapy

\- Git

\- Authorized network interface or PCAP file



Install Scapy with:



```bash

python -m pip install scapy


## Testing

The project includes unit tests for the redaction functions.

Run the tests with:

```bash
python -m unittest discover -s tests -v

