# MIT License
#
# Copyright (c) 2019 Weston Berg
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
'''
Module providing functionality for determining IP address connected to LAN
'''
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import netifaces
import socket
import subprocess

MAX_SCAN_WORKERS = 50           # Number of workers in pool
PING_CNT_ARG = '1'              # How many echo requests to send
PING_TIMEOUT_MS_ARG = '750'     # Timeout in ms


def __get_netmask(host_ip):
    '''
    Determines the netmask for the given host's IP address

    :param host_ip: IP to determine netmask for
    :returns: Netmask as formatted string (xxx.xxx.xxx.xxx)
    '''
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


def __ping_check(ip, queue):
    '''
    Pings given IP address and writes IP into queue if ping successful

    :param ip: IP to ping
    :param queue: Deque holding active IP addresses
    '''
    # Ping IP
    ping_args = ['ping', '-n', PING_CNT_ARG, '-w', PING_TIMEOUT_MS_ARG, ip]
    res = subprocess.run(ping_args,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.STDOUT)

    if res.returncode == 0:
        # IP active so add to queue
        queue.append(ip)


def execute():
    '''
    Runs the scan of the LAN

    :returns: List of active IP addresses in subnet
    '''
    # Deque of active IP addresses
    ip_queue = deque()

    # Get localhosts IP address
    host_ip_str = socket.gethostbyname(socket.gethostname())

    # Get netmask for localhost
    netmask = __get_netmask(host_ip_str)

    # Construct network localhost lives on
    net = ipaddress.ip_network(host_ip_str + '/' + netmask, strict=False)

    # Check for active IP addresses
    host_ip_addr = ipaddress.ip_address(host_ip_str)

    with ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as executor:
        # Scan all available host IPs on subnet
        for net_host_addr in net.hosts():
            # Skip localhost
            if net_host_addr != host_ip_addr:
                # Schedule active check
                executor.submit(__ping_check,
                                str(net_host_addr),
                                ip_queue)

    return list(ip_queue)
