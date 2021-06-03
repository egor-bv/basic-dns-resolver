"""
Выполнил Бойцов Егор
Группа 344

Recursive DNS Resolver
Supports IPv4 requests only
"""


import socket
import time
from typing import List, Optional
import dnslib.dns as dns


FALLBACK_DNS_SERVER_IP = "8.8.8.8"
BUFFER_SIZE = 4096

ROOT_IPS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10 ",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]

def print_log(*args, **kwargs):
    print(*args, **kwargs)

# maps name to record
GLOBAL_CACHE = dict()

def lookup_recursive(qname: str, qtype: dns.QTYPE, ip_set: List[str]) -> Optional[dns.DNSRecord]:
    if qname in GLOBAL_CACHE:
        print(f"FOUND RECORD IN CACHE FOR: {qname}")
        return GLOBAL_CACHE[qname]

    print(f"LOOKING UP: {qname} type={qtype} ON: {ip_set}\n")
    request = dns.DNSRecord()
    request.add_question(dns.DNSQuestion(qname, qtype))
    request.set_header_qa()
    for ip in ip_set:
        response = make_request(request, ip)
        if response:
            if response.rr:
                return response
            elif response.ar:
                new_ip_set = [str(r.rdata) for r in response.ar if r.rtype == dns.QTYPE.A]
                final_res = lookup_recursive(qname, qtype, new_ip_set)
                GLOBAL_CACHE[qname] = final_res
                return final_res
            elif response.auth:
                for auth_ns in response.auth:
                    if auth_ns.rtype == dns.QTYPE.NS:
                        auth_ns_res = lookup_recursive(str(auth_ns.rdata), dns.QTYPE.A, ROOT_IPS)
                        if auth_ns_res.rr:
                            GLOBAL_CACHE[str(auth_ns.rdata)] = auth_ns_res
                            for r in auth_ns_res.rr:
                                if r.rtype == dns.QTYPE.A:
                                    final_res = lookup_recursive(qname, qtype, [str(r.rdata)])
                                    if final_res:
                                        GLOBAL_CACHE[qname] = final_res
                                        return final_res
    return None


def process_packet(packet: bytes) -> Optional[dns.DNSRecord]:
    try:
        request = dns.DNSRecord.parse(packet)
        if request.q:
            if request.q.qtype != dns.QTYPE.A:
                print_log("Unsupported request type, redirecting to 8.8.8.8")
                response = make_request(request, FALLBACK_DNS_SERVER_IP)
                return response
            else:
                print_log("Servicing request...")
                reply_header = dns.DNSRecord.reply(request).header
                response = lookup_recursive(request.q.qname, request.q.qtype, ROOT_IPS)
                if response:
                    response.header = reply_header
                    response.set_header_qa()
                    print_log("GOT RESPONSE:")
                    print(response)
                    print()
                    return response
                else:
                    GLOBAL_CACHE[request.q.qname] = None
                    return dns.DNSRecord.reply(request)
    except dns.DNSError:
        print_log("DNS PACKET PARSING ERROR")
    return None

# Make DNS request to given IP
def make_request(request: dns.DNSRecord, ip: str) -> Optional[dns.DNSRecord]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    response = None
    try:
        sock.sendto(request.pack(), (ip, 53))
        packet, _ = sock.recvfrom(BUFFER_SIZE)
        response = dns.DNSRecord.parse(packet)
    except dns.DNSError:
        print_log("DNS PACKET PARSING ERROR")
    except socket.error:
        pass

    finally:
        sock.close()
    return response

def resolve(name: str):
    pass

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 53))
    print_log("DNS Resolver")
    print_log("Listening on 127.0.0.1:53...")
    try:
        while True:
            try:
                packet, ret_addr = sock.recvfrom(BUFFER_SIZE)
                response = process_packet(packet)
                if response:
                    sock.sendto(response.pack(), ret_addr)
            except socket.error:
                pass
                continue
    except KeyboardInterrupt:
        sock.close()
        exit(0)


if __name__ == "__main__":
    main()

