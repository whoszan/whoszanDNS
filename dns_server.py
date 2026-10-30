#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Итеративный DNS-сервер на Python с использованием dnspython.

Возможности:
  * Итеративный опрос серверов, ответственных за зону (начиная с корневых
    серверов, через TLD, далее по делегированию NS/glue-записям).
  * Поддержка нескольких типов записей: A, AAAA, MX, NS, TXT, CNAME, SOA,
    PTR, SRV и др. (любой тип, который понимает dnspython).
  * Кэш ответов, который сохраняется на диск (JSON) и переживает
    перезапуск сервера.
  * Одновременная работа с несколькими клиентами (ThreadingMixIn, UDP и TCP).
  * Интерактивное управление через терминал (команды cache/clear/save/exit).

Зависимости:
    pip install dnspython

Запуск (обычно нужны права администратора/root для порта 53):
    sudo python3 dns_server.py --port 53
    (или без sudo на непривилегированном порту)
    python3 dns_server.py --port 5353

Проверка:
    dig @127.0.0.1 -p 5353 example.com A
    nslookup -port=5353 example.com 127.0.0.1
"""

import argparse
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.exception


# --------------------------------------------------------------------------
# Корневые DNS-серверы (root hints), используются как отправная точка
# итеративного разрешения имён.
# --------------------------------------------------------------------------
ROOT_SERVERS = [
    "198.41.0.4",     # a.root-servers.net
    "199.9.14.201",   # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
    "199.7.91.13",    # d.root-servers.net
    "192.203.230.10", # e.root-servers.net
    "192.5.5.241",    # f.root-servers.net
    "192.112.36.4",   # g.root-servers.net
    "198.97.190.53",  # h.root-servers.net
    "192.36.148.17",  # i.root-servers.net
    "192.58.128.30",  # j.root-servers.net
    "193.0.14.129",   # k.root-servers.net
    "199.7.83.42",    # l.root-servers.net
    "202.12.27.33",   # m.root-servers.net
]

QUERY_TIMEOUT = 3.0      # таймаут одного UDP/TCP запроса к серверу, сек
MAX_HOPS = 20            # максимум шагов делегирования в итеративном резолве
NEGATIVE_TTL = 300       # TTL для кэширования отрицательных ответов (NXDOMAIN)

CACHE_FILE = "dns_cache.json"
cache_lock = threading.Lock()
cache = {}  # ключ "qname|QTYPE" -> {"rrsets": [...], "rcode": int, "expire": ts}


# ==========================================================================
#  Кэш: загрузка / сохранение / сериализация
# ==========================================================================
def load_cache():
    global cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            now = time.time()
            cache = {k: v for k, v in data.items() if v.get("expire", 0) > now}
            print(f"[cache] загружено {len(cache)} актуальных записей из {CACHE_FILE}")
        except Exception as e:
            print(f"[cache] не удалось загрузить кэш ({e}), начинаем с пустого")
            cache = {}
    else:
        cache = {}



def save_cache():
    with cache_lock:
        try:
            tmp_file = CACHE_FILE + ".tmp"
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)
            os.replace(tmp_file, CACHE_FILE)
        except Exception as e:
            print(f"[cache] ошибка сохранения кэша: {e}")


def cache_key(qname: dns.name.Name, qtype: int) -> str:
    return f"{qname.to_text().lower()}|{dns.rdatatype.to_text(qtype)}"


def serialize_rrset(rrset) -> dict:
    return {
        "name": rrset.name.to_text(),
        "ttl": rrset.ttl,
        "rdclass": dns.rdataclass.to_text(rrset.rdclass),
        "rdtype": dns.rdatatype.to_text(rrset.rdtype),
        "rdata": [rd.to_text() for rd in rrset],
    }


def deserialize_rrset(d: dict, ttl: int):
    if not d["rdata"]:
        return None
    return dns.rrset.from_text(d["name"], ttl, d["rdclass"], d["rdtype"], *d["rdata"])


def store_cache(key: str, answer, rcode: int):
    if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return  # временные ошибки (SERVFAIL и т.п.) не кэшируем
    ttl = NEGATIVE_TTL
    if answer:
        ttl = max(1, min(rr.ttl for rr in answer))
    with cache_lock:
        cache[key] = {
            "rrsets": [serialize_rrset(rr) for rr in answer],
            "rcode": int(rcode),
            "expire": time.time() + ttl,
        }
    threading.Thread(target=save_cache, daemon=True).start()


def lookup_cache(key: str):
    with cache_lock:
        entry = cache.get(key)
        if not entry:
            return None
        remaining = entry["expire"] - time.time()
        if remaining <= 0:
            del cache[key]
            return None
        rrsets = []
        ttl = max(1, int(remaining))
        for d in entry["rrsets"]:
            rr = deserialize_rrset(d, ttl)
            if rr is not None:
                rrsets.append(rr)
        return rrsets, entry["rcode"]


# ==========================================================================
#  Итеративное разрешение имён
# ==========================================================================
def query_nameservers(qname, qtype, nameservers, timeout=QUERY_TIMEOUT):
    """Опросить по очереди список IP-адресов серверов, вернуть первый ответ."""
    q = dns.message.make_query(qname, qtype)
    for ip in nameservers:
        try:
            resp = dns.query.udp(q, ip, timeout=timeout)
            if resp.flags & dns.flags.TC:
                # ответ обрезан - повторяем через TCP
                resp = dns.query.tcp(q, ip, timeout=timeout)
            return resp
        except (dns.exception.Timeout, OSError, dns.query.BadResponse,
                dns.exception.FormError, ConnectionError):
            continue
        except Exception:
            continue
    return None


def iterative_query(qname: dns.name.Name, qtype: int):
    """Собственно итеративное разрешение имени: начинаем с корневых
    серверов и следуем за делегированием (referral) до получения
    окончательного ответа."""
    nameservers = list(ROOT_SERVERS)
    visited = set()

    for _ in range(MAX_HOPS):
        response = query_nameservers(qname, qtype, nameservers)
        if response is None:
            return [], dns.rcode.SERVFAIL

        rcode = response.rcode()

        if response.answer:
            got_requested = any(rr.rdtype == qtype for rr in response.answer)
            if got_requested or qtype == dns.rdatatype.CNAME:
                return list(response.answer), rcode
            # возможно, получили CNAME вместо запрошенного типа - идём дальше
            cname_rr = next(
                (rr for rr in response.answer if rr.rdtype == dns.rdatatype.CNAME),
                None,
            )
            if cname_rr is not None:
                target = cname_rr[0].target
                sub_answer, sub_rcode = resolve(target, qtype)
                return list(response.answer) + list(sub_answer), sub_rcode
            return list(response.answer), rcode

        if rcode == dns.rcode.NXDOMAIN:
            return [], dns.rcode.NXDOMAIN

        if not response.authority:
            return [], rcode  # NODATA

        ns_rrsets = [rr for rr in response.authority if rr.rdtype == dns.rdatatype.NS]
        if not ns_rrsets:
            # вероятно SOA в authority -> NODATA / конец делегирования
            return [], rcode

        ns_names = [rr.target for rrset in ns_rrsets for rr in rrset]

        # ищем glue-записи (A) в additional section
        glue_ips = []
        for rrset in response.additional:
            if rrset.rdtype == dns.rdatatype.A and rrset.name in ns_names:
                glue_ips.extend(str(rr.address) for rr in rrset)

        if not glue_ips:
            # glue нет - разрешаем A-записи NS-серверов рекурсивно (через кэш/резолв)
            for ns_name in ns_names:
                try:
                    sub_answer, _ = resolve(ns_name, dns.rdatatype.A)
                    for rrset in sub_answer:
                        if rrset.rdtype == dns.rdatatype.A:
                            glue_ips.extend(str(rr.address) for rr in rrset)
                except Exception:
                    continue
                if glue_ips:
                    break

        if not glue_ips:
            return [], dns.rcode.SERVFAIL

        key = tuple(sorted(glue_ips))
        if key in visited:
            return [], dns.rcode.SERVFAIL
        visited.add(key)
        nameservers = glue_ips

    return [], dns.rcode.SERVFAIL


def resolve(qname, qtype: int):
    """Обёртка с кэшем. Принимает dns.name.Name либо строку."""
    if isinstance(qname, str):
        qname = dns.name.from_text(qname)
    if not qname.is_absolute():
        qname = qname.concatenate(dns.name.root)

    key = cache_key(qname, qtype)
    hit = lookup_cache(key)
    if hit is not None:
        return hit

    answer, rcode = iterative_query(qname, qtype)
    store_cache(key, answer, rcode)
    return answer, rcode


# ==========================================================================
#  Обработка DNS-запросов (построение ответа)
# ==========================================================================
def build_response(request: dns.message.Message, client_ip: str) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.flags |= dns.flags.RA  # recursion available

    if not request.question:
        response.set_rcode(dns.rcode.FORMERR)
        return response

    q = request.question[0]
    qname = q.name
    qtype = q.rdtype

    print(f"[{time.strftime('%H:%M:%S')}] {client_ip:<15} -> "
          f"{qname.to_text():<40} {dns.rdatatype.to_text(qtype)}")

    try:
        answer, rcode = resolve(qname, qtype)
        for rrset in answer:
            response.answer.append(rrset)
        response.set_rcode(rcode)
    except Exception as e:
        print(f"[ошибка] {e}")
        response.set_rcode(dns.rcode.SERVFAIL)

    return response


# ==========================================================================
#  Сетевые обработчики (UDP + TCP), многопоточный сервер
# ==========================================================================
class DNSHandlerUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        client_ip = self.client_address[0]
        try:
            request = dns.message.from_wire(data)
        except Exception:
            return
        response = build_response(request, client_ip)
        try:
            sock.sendto(response.to_wire(), self.client_address)
        except Exception:
            pass


class ThreadingUDPDNSServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


class DNSHandlerTCP(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            length_data = self._recv_exact(2)
            if length_data is None:
                return
            (length,) = struct.unpack("!H", length_data)
            data = self._recv_exact(length)
            if data is None:
                return
            request = dns.message.from_wire(data)
            response = build_response(request, self.client_address[0])
            wire = response.to_wire()
            self.request.sendall(struct.pack("!H", len(wire)) + wire)
        except Exception:
            pass

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


class ThreadingTCPDNSServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ==========================================================================
#  Терминальный интерфейс
# ==========================================================================
def print_help():
    print("""
Доступные команды:
  cache        - показать содержимое кэша
  clear        - очистить кэш (в памяти и на диске)
  save         - принудительно сохранить кэш на диск
  stats        - показать количество записей в кэше
  help         - показать эту справку
  exit / quit  - остановить сервер и выйти
""")


def print_cache():
    with cache_lock:
        if not cache:
            print("Кэш пуст")
            return
        now = time.time()
        print(f"{'ИМЯ':<40} {'ТИП':<8} {'TTL':<6} ЗНАЧЕНИЯ")
        for key, entry in cache.items():
            name, qtype = key.split("|")
            ttl = max(0, int(entry["expire"] - now))
            if entry["rcode"] == dns.rcode.NXDOMAIN:
                print(f"{name:<40} {qtype:<8} {ttl:<6} NXDOMAIN")
                continue
            values = []
            for rr in entry["rrsets"]:
                values.extend(rr["rdata"])
            print(f"{name:<40} {qtype:<8} {ttl:<6} {', '.join(values) if values else '(нет данных)'}")


def terminal_loop(udp_server, tcp_server):
    print_help()
    while True:
        try:
            cmd = input("dns> ").strip()
        except EOFError:
            break
        if cmd in ("exit", "quit"):
            break
        elif cmd == "help":
            print_help()
        elif cmd == "cache":
            print_cache()
        elif cmd == "clear":
            with cache_lock:
                cache.clear()
            save_cache()
            print("Кэш очищен")
        elif cmd == "save":
            save_cache()
            print("Кэш сохранён на диск")
        elif cmd == "stats":
            with cache_lock:
                print(f"Записей в кэше: {len(cache)}")
        elif cmd == "":
            continue
        else:
            print("Неизвестная команда. Наберите 'help' для справки.")


# ==========================================================================
#  main
# ==========================================================================
def main():
    global CACHE_FILE

    parser = argparse.ArgumentParser(description="Итеративный DNS-сервер на Python")
    parser.add_argument("--host", default="0.0.0.0", help="адрес для прослушивания (по умолчанию 0.0.0.0)")
    parser.add_argument("--port", type=int, default=53, help="порт (по умолчанию 53, требует прав администратора)")
    parser.add_argument("--cache-file", default=CACHE_FILE, help="файл для хранения кэша между перезапусками")
    args = parser.parse_args()

    CACHE_FILE = args.cache_file
    load_cache()

    try:
        udp_server = ThreadingUDPDNSServer((args.host, args.port), DNSHandlerUDP)
        tcp_server = ThreadingTCPDNSServer((args.host, args.port), DNSHandlerTCP)
    except PermissionError:
        print(f"Нет прав на привязку к порту {args.port}.")
        print("Запустите с правами администратора/root, либо укажите другой порт: --port 5353")
        sys.exit(1)
    except OSError as e:
        print(f"Не удалось запустить сервер на {args.host}:{args.port} - {e}")
        sys.exit(1)

    threading.Thread(target=udp_server.serve_forever, daemon=True).start()
    threading.Thread(target=tcp_server.serve_forever, daemon=True).start()

    print("=" * 70)
    print(f"Итеративный DNS-сервер запущен на {args.host}:{args.port} (UDP и TCP)")
    print(f"Файл кэша: {os.path.abspath(CACHE_FILE)}")
    print("=" * 70)

    try:
        terminal_loop(udp_server, tcp_server)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nЗавершение работы, сохранение кэша...")
        save_cache()
        udp_server.shutdown()
        tcp_server.shutdown()
        udp_server.server_close()
        tcp_server.server_close()
        print("Сервер остановлен. До свидания!")


if __name__ == "__main__":
    main()
