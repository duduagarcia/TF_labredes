import socket
import struct
import time
import ipaddress
import threading


def calculate_checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = (source_string[count+1]) * 256 + (source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + (source_string[len(source_string) - 1])
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_icmp_packet(seq_number):
    icmp_type = 8  # ICMP Echo Request
    icmp_code = 0
    my_checksum = 0
    identifier = 1
    header = struct.pack("bbHHh", icmp_type, icmp_code, my_checksum, identifier, seq_number)
    data = struct.pack("d", time.time())
    my_checksum = calculate_checksum(header + data)
    header = struct.pack("bbHHh", icmp_type, icmp_code, socket.htons(my_checksum), identifier, seq_number)
    return header + data


def send_icmp_request(destination_ip, timeout, seq_number, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout / 1000.0)
        packet = create_icmp_packet(seq_number)
        sock.sendto(packet, (destination_ip, 1))
        start_time = time.time()
        response, addr = sock.recvfrom(1024)
        end_time = time.time()
        icmp_header = response[20:28]
        type, code, checksum, p_id, sequence = struct.unpack("bbHHh", icmp_header)
        if type == 0 and sequence == seq_number:  # ICMP Echo Reply
            duration = (end_time - start_time) * 1000  # Convert to ms
            results[destination_ip] = duration
    except socket.timeout:
        results[destination_ip] = None
    finally:
        sock.close()


def icmp_scan(network, timeout):
    network = ipaddress.ip_network(network, strict=False)
    threads = []
    results = {}
    seq_number = 1

    for ip in network.hosts():
        t = threading.Thread(target=send_icmp_request, args=(str(ip), timeout, seq_number, results))
        threads.append(t)
        t.start()
        seq_number += 1

    for t in threads:
        t.join()

    active_hosts = {ip: time for ip, time in results.items() if time is not None}
    return active_hosts, len(active_hosts), len(results)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Uso: python scanner.py <rede/máscara> <tempo limite em ms>")
        sys.exit(1)

    network = sys.argv[1]
    timeout = int(sys.argv[2])

    start_time = time.time()
    active_hosts, num_active, num_scanned = icmp_scan(network, timeout)
    end_time = time.time()
    total_time = (end_time - start_time) * 1000  # Convert to ms

    print(f"Hosts ativos:")
    for host, response_time in active_hosts.items():
        print(f"{host} - {response_time:.2f} ms")

    print(f"Total de hosts ativos: {num_active}")
    print(f"Total de hosts escaneados: {num_scanned}")
    print(f"Tempo total da varredura: {total_time:.2f} ms")

    