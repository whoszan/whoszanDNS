import socket
import struct
import sys

def build_dns_query(domain):
    """Собирает байты запроса"""
    return (
        struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
        + b''.join(bytes([len(p)]) + p.encode() for p in domain.split('.')) + b'\x00'
        + struct.pack('!HH', 1, 1) # Тип A (IPv4)
    )

def parse_response(data):
    """Разбирает ответ: ищет IP или CNAME"""
    try:
        _, _, qd, an, _, _ = struct.unpack('!HHHHHH', data[:12])
        offset = 12
        # Пропускаем вопрос
        for _ in range(qd):
            while data[offset] != 0:
                if (data[offset] & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += data[offset] + 1
            else:
                offset += 1
            offset += 4

        # Читаем ответы
        for _ in range(an):
            if (data[offset] & 0xC0) == 0xC0:
                offset += 2
            else:
                while data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1

            rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[offset:offset+10])
            offset += 10

            if rtype == 1 and rdlen == 4: # Тип A (IPv4)
                return 'IP', socket.inet_ntoa(data[offset:offset+4])
            elif rtype == 5: # Тип CNAME (Псевдоним)
                parts = []
                c_off = offset
                while c_off < len(data) and data[c_off] != 0:
                    if (data[c_off] & 0xC0) == 0xC0:
                        break
                    l = data[c_off]
                    parts.append(data[c_off+1:c_off+1+l].decode('utf-8', 'ignore'))
                    c_off += l + 1
                return 'CNAME', '.'.join(parts)

            offset += rdlen
    except Exception:
        pass
    return None, None

def ask_dns(domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    query = build_dns_query(domain)
    sock.sendto(query, ('127.0.0.1', 1053))
    try:
        data, _ = sock.recvfrom(512)
        return parse_response(data)
    except socket.timeout:
        return None, "Таймаут"
    finally:
        sock.close()

def test_domain(target):
    print(f"Запрашиваем: {target}")

    rec_type, val = ask_dns(target)

    if rec_type == 'IP':
        print(f"   УСПЕХ! Найден IP-адрес: {val}")

    elif rec_type == 'CNAME':
        print(f"   Получен CNAME (псевдоним): {val}")
        print(f"   Запрашиваем IP для псевдонима '{val}'...")
        
        rec_type2, val2 = ask_dns(val)
        if rec_type2 == 'IP':
            print(f"   УСПЕХ! Финальный IP-адрес: {val2}")
        else:
            print(f"   Результат для псевдонима: {val2}")
    else:
        print(f"   Ошибка или нет ответа: {val}")


if __name__ == '__main__':
    # Если передали сайт через аргумент команды (например: python test.py google.com)
    if len(sys.argv) > 1:
        domains_to_test = sys.argv[1:]
    else:
        # Если ничего не передали, проверяем список по умолчанию
        domains_to_test = ["google.com", "vk.com"]

    for d in domains_to_test:
        test_domain(d)