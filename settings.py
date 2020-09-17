import os

from dotenv import load_dotenv
load_dotenv()


DISCORD_MUTE_URL = os.getenv("DISCORD_MUTE_URL")
DISCORD_UNMUTE_URL = os.getenv("DISCORD_UNMUTE_URL")
