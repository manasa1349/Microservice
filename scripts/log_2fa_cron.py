#!/usr/bin/env python3
import sys
sys.path.append("/app")

import os
from datetime import datetime, timezone
from app.totp_utils import generate_totp_code

SEED_FILE = "/data/seed.txt"
LOG_FILE = "/cron/last_code.txt"

def main():
    # 1. Read seed
    if not os.path.exists(SEED_FILE):
        print("Seed file not found", flush=True)
        return

    try:
        with open(SEED_FILE, "r") as f:
            hex_seed = f.read().strip()
    except Exception as e:
        print(f"Error reading seed: {e}", flush=True)
        return

    # 2. Generate TOTP
    try:
        code = generate_totp_code(hex_seed)
    except Exception as e:
        print(f"Error generating TOTP: {e}", flush=True)
        return

    # 3. Generate timestamp in UTC
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # 4. Append log entry
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{timestamp} - 2FA Code: {code}\n")
    except Exception as e:
        print(f"Error writing cron log: {e}", flush=True)

if __name__ == "__main__":
    main()