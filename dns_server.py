import socket
import struct
import threading

#корневой днс сервер
ROOT = ['198.41.0.4']

#Вспомогательная функция для чтением N байт по TCP
def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

#Превращает домен в байты DNS-формата
def encode_domain(name):
    parts = name.encode().split(b'.')
    result = b''
    for p in parts:
        if p:
            result += len(p).to_bytes(1) + p
    return result + b'\x00'


#Декодирует домен из байт
def decode_domain(data, offset):
    parts, orig = [], None
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return '.'.join(parts), (orig or offset + 1)
        if (length & 0xC0) == 0xC0:
            ptr = struct.unpack('!H', data[offset: offset + 2])[0] & 0x3FFF
            orig = orig or offset + 2
            offset = ptr
            continue
        offset += 1
        parts.append(data[offset: offset + length].decode('utf-8', 'ignore'))
        offset += length
    return '.'.join(parts), orig or offset

#Разбирает ответный DNS-пакет от внешнего сервера
def parse_response(resp):
    if len(resp) < 12:
        return b'', 0, [], {}, 2
    flags = struct.unpack('!H', resp[2:4])[0]
    rcode = flags & 0x000F
    _, _, qd, an, ns, ar = struct.unpack('!HHHHHH', resp[:12])
    offset = 12
    for _ in range(qd):
        _, offset = decode_domain(resp, offset)
        offset += 4

    ans_start = offset
    for _ in range(an):
        _, offset = decode_domain(resp, offset)
        offset += 10 + struct.unpack('!H', resp[offset + 8: offset + 10])[0]
    ans_end = offset

    ns_recs = []
    for _ in range(ns):
        _, offset = decode_domain(resp, offset)
        rtype, _, _, rdlen = struct.unpack('!HHIH', resp[offset: offset + 10])
        offset += 10
        if rtype == 2:
            ns_recs.append(decode_domain(resp, offset)[0])
        offset += rdlen

    glue = {}
    for _ in range(ar):
        name, offset = decode_domain(resp, offset)
        rtype, _, _, rdlen = struct.unpack('!HHIH', resp[offset: offset + 10])
        offset += 10
        if rtype == 1 and rdlen == 4:
            glue[name.lower()] = socket.inet_ntoa(resp[offset: offset + 4])
        offset += rdlen

    return resp[ans_start:ans_end], an, ns_recs, glue, rcode

#Итеративный поиск
def resolve(query):
    qname, offset = decode_domain(query, 12)
    qtype, qclass = struct.unpack('!HH', query[offset: offset + 4])

    servers = ROOT
    for _ in range(5):
        next_s = []
        for ip in servers:
            try:
                packet = struct.pack('!HHHHHH', 0x1234, 0x0000, 1, 0, 0, 0) + encode_domain(qname) + struct.pack('!HH',
                                                                                                                 qtype,
                                                                                                                 qclass)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2)
                    s.sendto(packet, (ip, 53))
                    resp, _ = s.recvfrom(512)
                ans, an_count, ns_recs, glue, rcode = parse_response(resp)
                if an_count > 0 or rcode != 0:
                    return ans, an_count, rcode
                next_s.extend(glue[n.lower()] for n in ns_recs if n.lower() in glue)
            except:
                continue
        if not next_s:
            break
        servers = next_s
    return None, 0, 2

#Формирует DNS-ответ для клиента
def process_query(data):
    tx_id = struct.unpack('!H', data[:2])[0]

    request_flags = struct.unpack('!H', data[2:4])[0]

    qname, offset = decode_domain(data, 12)
    ans, an_count, rcode = resolve(data)
    flags = (request_flags & 0x7FF0) | 0x8000 | rcode
    
    if an_count == 0:
        return struct.pack('!HHHHHH', tx_id, flags, 1, 0, 0, 0) + data[12:offset + 4]
    return struct.pack('!HHHHHH', tx_id, flags, 1, an_count, 0, 0) + data[12:offset + 4] + ans

#Обработка одного клиента по TCP
def handle_tcp(conn):
    try:
        length_bytes = recvall(conn, 2)
        if length_bytes:
            length = struct.unpack('!H', length_bytes)[0]
            data = recvall(conn, length)
            if data:
                resp = process_query(data)
                conn.sendall(struct.pack('!H', len(resp)) + resp)
    except:
        pass
    finally:
        conn.close()


#Обработка одного клиента по UDP
def handle_udp(udp, data, addr):
    try:
        response = process_query(data)
        udp.sendto(response, addr)
    except:
        pass

#Запуск udp сервера
def run_udp():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 1053))
    while True:
        data, addr = udp.recvfrom(512)
        threading.Thread(target=handle_udp, args=(udp, data, addr), daemon=True).start()

#Запуск tcp сервера
def run_tcp():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('127.0.0.1', 1053))
    tcp.listen(5)
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=handle_tcp, args=(conn,)).start()


if __name__ == '__main__':
    threading.Thread(target=run_udp, daemon=True).start()
    threading.Thread(target=run_tcp, daemon=True).start()

    print('DNS running on 127.0.0.1:1053')
    threading.Event().wait()