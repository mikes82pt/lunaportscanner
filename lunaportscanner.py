from __future__ import annotations
import argparse
import asyncio
import socket
import sys
from typing import List, Tuple

from colorama import Fore, Style, init

# Initialize colorama (works on Windows terminals)
init(autoreset=True)

__version__ = "2.1"

# Defaults
DEFAULT_TIMEOUT = 1.0
DEFAULT_CONCURRENCY = 200


class UDPClient(asyncio.DatagramProtocol):
    def __init__(self, on_response: asyncio.Future):
        self.on_response = on_response

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        # Mark that we received data
        if not self.on_response.done():
            self.on_response.set_result(True)

    def error_received(self, exc):
        # Some UDP sockets may receive ICMP errors here
        if not self.on_response.done():
            self.on_response.set_exception(exc)


async def scan_tcp(ip: str, port: int, family: int, results: List[str], sem: asyncio.Semaphore, timeout: float):
    """Async TCP scan with timeout and concurrency control."""
    try:
        async with sem:
            conn_coro = asyncio.open_connection(host=ip, port=port, family=family)
            reader, writer = await asyncio.wait_for(conn_coro, timeout=timeout)
            results.append(Fore.GREEN + f"TCP {port} Open")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except asyncio.TimeoutError:
        # treat as filtered/closed
        pass
    except (ConnectionRefusedError, OSError):
        pass
    except Exception:
        pass


async def scan_udp(ip: str, port: int, family: int, results: List[str], sem: asyncio.Semaphore, timeout: float):
    """Async UDP scan — send an empty datagram and wait briefly for a response or ICMP error."""
    loop = asyncio.get_event_loop()
    try:
        async with sem:
            on_response = loop.create_future()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPClient(on_response),
                remote_addr=(ip, port),
                family=family,
            )
            try:
                # Send an empty datagram (some services respond to this)
                transport.sendto(b"")
                try:
                    await asyncio.wait_for(on_response, timeout=timeout)
                    results.append(Fore.GREEN + f"UDP {port} Open")
                except asyncio.TimeoutError:
                    # No response — commonly means open|filtered
                    results.append(Fore.YELLOW + f"UDP {port} Open|Filtered")
                except Exception:
                    # Treat errors as filtered/closed
                    pass
            finally:
                try:
                    transport.close()
                except Exception:
                    pass
    except Exception:
        # Could be network errors, unreachable, etc.
        pass


async def scan_target(ip: str, family: int, ports: List[int], protocols: List[str], concurrency: int, timeout: float) -> List[str]:
    """Scan all ports for one IP and return results list."""
    results: List[str] = []
    sem = asyncio.Semaphore(concurrency)
    tasks = []
    for port in ports:
        if "TCP" in protocols:
            tasks.append(scan_tcp(ip, port, family, results, sem, timeout))
        if "UDP" in protocols:
            tasks.append(scan_udp(ip, port, family, results, sem, timeout))

    if tasks:
        await asyncio.gather(*tasks)
    return results


def resolve_target(target: str) -> List[Tuple[str, int]]:
    """Resolve domain/IP to list of (IP, family)."""
    try:
        results = []
        # AF_UNSPEC will return both IPv4 and IPv6 addresses when available
        for addr in socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            ip = addr[4][0]
            family = addr[0]
            if (ip, family) not in results:
                results.append((ip, family))
        return results
    except Exception as e:
        print(Fore.RED + f"[!] Could not resolve {target}: {e}")
        return []


def parse_ports(ports_str: str) -> List[int]:
    """Parse a single port or a range like 20-25 or comma separated list."""
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start_i = int(start)
                end_i = int(end)
                if start_i <= end_i:
                    ports.update(range(start_i, end_i + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 0 < p <= 65535)


def protocols_from_str(s: str) -> List[str]:
    s = s.strip().upper()
    if s == 'TCP':
        return ['TCP']
    if s == 'UDP':
        return ['UDP']
    if s == 'BOTH':
        return ['TCP', 'UDP']
    # default
    return ['TCP']


async def run_interactive(timeout: float, concurrency: int):
    print(Style.BRIGHT + Fore.CYAN + f"Luna Port Scanner {__version__}")

    while True:
        target = input("Enter a domain or IP address: ").strip()
        if not target:
            continue

        port_input = input("Enter port (single), range (20-25) or comma list (80,443): ").strip()
        ports = parse_ports(port_input)
        if not ports:
            print(Fore.RED + "[!] No valid ports provided.")
            continue

        proto_input = input("Enter protocol (TCP/UDP/BOTH): ").strip()
        protocols = protocols_from_str(proto_input)

        resolved = resolve_target(target)
        if not resolved:
            continue

        for ip, family in resolved:
            fam_str = "IPv6" if family == socket.AF_INET6 else "IPv4"
            print(Style.BRIGHT + Fore.MAGENTA + f"\n--- Scanning {ip} ({fam_str}) ---")
            results = await scan_target(ip, family, ports, protocols, concurrency, timeout)

            if results:
                for r in sorted(results):
                    print("   " + r)
            else:
                print(Fore.RED + "   No open ports found")

        if input("\nScan another target? (y/n): ").strip().lower() != 'y':
            break


async def run_noninteractive(target: str, ports: List[int], protocols: List[str], timeout: float, concurrency: int):
    resolved = resolve_target(target)
    if not resolved:
        return

    for ip, family in resolved:
        fam_str = "IPv6" if family == socket.AF_INET6 else "IPv4"
        print(Style.BRIGHT + Fore.MAGENTA + f"\n--- Scanning {ip} ({fam_str}) ---")
        results = await scan_target(ip, family, ports, protocols, concurrency, timeout)

        if results:
            for r in sorted(results):
                print("   " + r)
        else:
            print(Fore.RED + "   No open ports found")


def main():
    parser = argparse.ArgumentParser(description="Luna Port Scanner 2.0")
    parser.add_argument('-t', '--target', help='Target host (domain or IP)')
    # Make --ports optional so we can prompt for it when target is provided
    parser.add_argument('-p', '--ports', default=None, help='Ports: single, range (20-25) or comma list (80,443)')
    parser.add_argument('--protocol', default='TCP', help='Protocol: TCP, UDP or BOTH')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help='Connection timeout in seconds')
    parser.add_argument('--concurrency', type=int, default=DEFAULT_CONCURRENCY, help='Max concurrent connections')
    parser.add_argument('--version', action='store_true', help='Show version and exit')

    args = parser.parse_args()

    if args.version:
        print(f"Luna Port Scanner {__version__}")
        return

    timeout = args.timeout
    concurrency = max(1, args.concurrency)

    if args.target:
        # If ports weren't supplied on the command line, prompt the user (so ranges like 20-25 won't be parsed as flags)
        ports_str = args.ports
        if ports_str is None:
            try:
                # Prompt for ports (this will accept ranges like 20-25 safely)
                ports_str = input("Enter port (single), range (20-25) or comma list (80,443): ").strip()
            except KeyboardInterrupt:
                print("\nExiting...")
                return

        if not ports_str:
            print(Fore.RED + "[!] No ports provided.")
            return

        ports = parse_ports(ports_str)
        protocols = protocols_from_str(args.protocol)
        if not ports:
            print(Fore.RED + "[!] No valid ports specified.")
            return
        asyncio.run(run_noninteractive(args.target, ports, protocols, timeout, concurrency))
    else:
        try:
            asyncio.run(run_interactive(timeout, concurrency))
        except KeyboardInterrupt:
            print('\nExiting...')


if __name__ == '__main__':
    main()
