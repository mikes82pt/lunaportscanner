import socket
import threading
import sys

def test_port(ip, port, protocol):
    try:
        if protocol == 'TCP':
            with socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    print(f"Port {port} is open on {ip} (TCP)")
                else:
                    print(f"Port {port} is closed on {ip} (TCP)")
        elif protocol == 'UDP':
            with socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                sock.sendto(b'', (ip, port))
                print(f"Port {port} is open on {ip} (UDP) - No response means open or filtered")
    except Exception as e:
        print(f"Error testing port {port} on {ip}: {e}")

def test_domain(domain, port, protocol):
    try:
        # Get both IPv4 and IPv6 addresses
        addresses = socket.getaddrinfo(domain, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for addr in addresses:
            ip = addr[4][0]
            test_port(ip, port, protocol)
    except Exception as e:
        print(f"Error resolving domain {domain}: {e}")

def main():
    print("Luna Port Scanner 1.0")
    
    domain = input("Enter a domain or IP address: ")
    port = int(input("Enter a port number: "))
    protocol = input("Enter protocol (TCP/UDP): ").strip().upper()

    if protocol not in ['TCP', 'UDP']:
        print("Invalid protocol. Please enter TCP or UDP.")
        return

    while True:
        test_domain(domain, port, protocol)

        # Ask if the user wants to repeat the same test
        repeat = input("Do you want to repeat the same test? (y/n): ").strip().lower()
        if repeat != 'y':
            break

    # Option to test another port
    while True:
        cont = input("Do you want to test another port? (y/n): ").strip().lower()
        if cont == 'y':
            domain = input("Enter a domain or IP address: ")
            port = int(input("Enter a port number: "))
            protocol = input("Enter protocol (TCP/UDP): ").strip().upper()

            if protocol not in ['TCP', 'UDP']:
                print("Invalid protocol. Please enter TCP or UDP.")
                continue
            test_domain(domain, port, protocol)
        else:
            break

if __name__ == "__main__":
    main()
