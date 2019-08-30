'''
Module providing functionality for determining IP address connected to LAN
'''
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import netifaces
import socket

MAX_SCAN_WORKERS = 100


def get_netmask(host_ip):
    netmask = ''  # Netmask for given adapter IP

    # Get list of network adapters
    net_adapters = netifaces.interfaces()

    # Search through list for appropriate adapter
    for adapter in net_adapters:
        # Get adapter info
        adapter_info = netifaces.ifaddresses(adapter)

        # Filter to only AF_INET address family (list of dicts of addresses)
        af_inet_addresses = adapter_info[netifaces.AF_INET]

        # Check addresses for host IP
        for addr_dict in af_inet_addresses:
            if addr_dict['addr'] == host_ip:
                # Match found, retrieve netmask
                netmask = addr_dict['netmask']

    return netmask


def sock_addr_resolution_check(ip, queue):
    try:
        socket.gethostbyaddr(ip)
        queue.append(ip)

    except (socket.herror, socket.gaierror):
        pass


def ping_check(ip, queue):
    pass


def lan_scan():
    # Deque of active IP addresses
    ip_queue = deque()

    # Get localhosts IP address
    host_ip_str = socket.gethostbyname(socket.gethostname())

    # Get netmask for localhost
    netmask = get_netmask(host_ip_str)

    # Construct network localhost lives on
    net = ipaddress.ip_network(host_ip_str + '/' + netmask, strict=False)

    # Check for active IP addresses
    host_ip_addr = ipaddress.ip_address(host_ip_str)

    with ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as executor:
        for net_host_addr in net.hosts():
            # Skip localhost
            if net_host_addr != host_ip_addr:
                # Schedule active check
                executor.submit(sock_addr_resolution_check,
                                net_host_addr.exploded,
                                ip_queue)

    return list(ip_queue)


if __name__ == '__main__':
    print(lan_scan())
