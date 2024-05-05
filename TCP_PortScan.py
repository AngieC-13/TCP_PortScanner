import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import IP, TCP, sr

# Personal Notes: VsCode hates me, check if it is the right version. Bottom right corner. 
#               the 3.11.8 64-bit works. 

# Ask for a host IP you would like to scan
ask_IP = input('What is the IP you want to see? ')

# Define the port range to scan
port_range = range(1, 23)  # Adjust this for your desired range

num_open_ports = 0
num_closed_ports = 0
num_no_response = 0

for port in port_range:
    # Send SYN packet to the current port
    resc, unans = sr(IP(dst=ask_IP) / TCP(flags="S", dport=port), timeout=60)

    # Check for open ports
    if resc:
        for s, r in resc:
            if r.haslayer(TCP):
                # Check for RST (rejected) or SYN-ACK (accepted) packets
                if r[TCP].flags == 0x18:  # RST flag
                    num_closed_ports += 1
                    print(f"Port {port} is closed.")
                else:
                    num_open_ports += 1
                    print(f"Port {port} is open!")
    else:
        num_no_response += 1
        print(f"Port {port} - No response received (possibly closed).")

# Print summary
print(f"\nScan results:")
print(f"Open ports: {num_open_ports}")
print(f"Closed ports: {num_closed_ports}")
print(f"No response: {num_no_response}")
