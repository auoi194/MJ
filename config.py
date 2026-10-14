# config.py — valan bot + api config
import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN       = os.getenv("BOT_TOKEN", "")
GUILD_ID        = int(os.getenv("GUILD_ID", "0"))
PANEL_USERNAME  = os.getenv("PANEL_USERNAME", "valannnnnnnnnnnnnnnnnnnnnnnnnn")
API_HOST        = os.getenv("API_HOST", "0.0.0.0")
API_PORT        = int(os.getenv("API_PORT", "8080"))
API_PUBLIC      = os.getenv("API_PUBLIC", "https://api.valan.shop")
API_SELF        = os.getenv("API_SELF", "http://127.0.0.1:8080")
DB_PATH         = os.getenv("DB_PATH", "valan.db")
MAX_CONCURRENT  = int(os.getenv("MAX_CONCURRENT", "6"))
MAX_TIME        = int(os.getenv("MAX_TIME", "250"))
BOT_EMOJI       = os.getenv("BOT_EMOJI", "<a:star:0000000000000000000>")

# emoji placeholders — replace with the real IDs from your server
EMO_STAR        = os.getenv("EMO_STAR", "<a:1000030144:1559280351254151199>")
EMO_WALLET      = os.getenv("EMO_WALLET", "<:wallet:0000000000000000000>")
EMO_BOLT        = os.getenv("EMO_BOLT",   "<:bolt:0000000000000000000>")
EMO_BUTTON      = os.getenv("EMO_BUTTON", "<:1000039186:1559961315642966026>")

# panel color (dark, blends with discord dark background = "no border" look)
PANEL_COLOR     = 0x2b2d31

# target restrictions enforced by the BOT (not the API)
FORBIDDEN_TLDS  = (".th", ".gov", ".go.th", ".ac.th", ".mi.th")