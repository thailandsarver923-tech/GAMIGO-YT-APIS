import json
import time
import asyncio
import httpx
import subprocess
import os
import requests
import base64
from typing import Dict, Optional

# --- Settings ---
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
TELEGRAM_TOKEN = "7087819906:AAGgZOrMlE7SWxs_H0uvGu-YKvS7kyqTPQ8"
TELEGRAM_CHAT_ID = 6761595092
BRANCH_NAME = "main"
JWT_API_URL = "https://momin-jwt.vercel.app/token"
KEY_CHECK_URL = "https://no-like-api1.vercel.app/api/key/check?key=Gamigo2"

# --- Region Config ---
REGION_CONFIG = {
    "IND": {"input": "uid_IND.json", "output": "token_ind.json"},
    "BD": {"input": "uid_BD.json", "output": "token_bd.json"},
    "BR": {"input": "uid_BR.json", "output": "token_na.json"},  # BR → NA output
}

# --- Telegram ---
def send_telegram_message(message: str, repeat: int = 1):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    for _ in range(repeat):
        try:
            requests.post(url, data=data, timeout=15)
        except Exception:
            pass

# --- Git Helpers ---
def run_git_command(cmd: str) -> str:
    try:
        result = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True
        )
        return result.strip()
    except subprocess.CalledProcessError as e:
        return e.output.strip()

def detect_git_conflict() -> bool:
    status = run_git_command("git status")
    return "both modified" in status or "Unmerged paths" in status

def resolve_git_conflict():
    print("\n⚠️ Git Conflict Detected. Resolving...")
    run_git_command("git add .")
    run_git_command("git commit -m 'resolve conflict' || true")
    run_git_command("git rebase --continue || true")

def push_to_git():
    run_git_command(f"git checkout {BRANCH_NAME}")
    run_git_command(f"git fetch origin {BRANCH_NAME}")
    run_git_command(f"git reset --hard origin/{BRANCH_NAME}")
    run_git_command(f"git add .")
    run_git_command(f"git commit -m 'update tokens' || true")
    run_git_command(f"git push origin {BRANCH_NAME}")
    print(f"🚀 Changes pushed to {BRANCH_NAME} branch.")

# --- Batch Fetcher ---
def get_batch_count() -> int:
    try:
        resp = requests.get(KEY_CHECK_URL, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            return int(data.get("batch_count", 0))
        return 0
    except Exception:
        return 0

# --- JWT Helpers ---
def decode_jwt(token: str) -> dict:
    """Decode JWT payload without verifying (to check lock_region)"""
    try:
        payload_part = token.split(".")[1]
        padded = payload_part + "=" * (-len(payload_part) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except Exception:
        return {}

async def generate_jwt_token(client, uid: str, password: str) -> Optional[str]:
    try:
        url = f"{JWT_API_URL}?uid={uid}&password={password}"
        headers = {"User-Agent": USERAGENT, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("token")
        return None
    except Exception as e:
        print(f"Error generating token for {uid}: {str(e)}")
        return None

async def process_account_with_retry(client, region: str, uid: str, password: str, max_retries: int = 2):
    for attempt in range(max_retries):
        token = await generate_jwt_token(client, uid, password)
        if token:
            if region == "BD":
                payload = decode_jwt(token)
                if payload.get("lock_region") in ["BR", "US", "SAC", "NA"]:
                    print(f"🚫 UID {uid} skipped (lock_region={payload.get('lock_region')})")
                    return None
            return {"uid": uid, "token": token}

        if attempt < max_retries - 1:
            print(f"⏳ Retry UID {uid} after 1 min...")
            await asyncio.sleep(60)

    send_telegram_message(f"❌ Token generation failed for UID {uid}", repeat=2)
    return None

async def generate_tokens_for_region(region: str):
    cfg = REGION_CONFIG[region]
    input_file = cfg["input"]
    output_file = cfg["output"]

    if not os.path.exists(input_file):
        msg = f"⚠️ Input file missing: {input_file} → skipped"
        print(msg)
        send_telegram_message(msg)
        return

    with open(input_file, "r") as f:
        accounts = json.load(f)

    total_accounts = len(accounts)
    batch_count = get_batch_count() or (total_accounts + 99) // 100
    batch_size = (total_accounts + batch_count - 1) // batch_count
    accounts_sliced = accounts[:batch_size]

    if not accounts_sliced:
        msg = f"⚠️ No accounts found in {input_file}"
        print(msg)
        send_telegram_message(msg)
        return

    print(f"🚀 Starting {region} Batch (1/{batch_count}) ({len(accounts_sliced)} accounts)")
    send_telegram_message(f"🚀 Starting {region} Batch (1/{batch_count}) ({len(accounts_sliced)} accounts)")

    tokens = []
    async with httpx.AsyncClient() as client:
        tasks = [process_account_with_retry(client, region, acc["uid"], acc["password"]) for acc in accounts_sliced]
        results = await asyncio.gather(*tasks)
        tokens = [r for r in results if r]

    with open(output_file, "w") as f:
        json.dump(tokens, f, indent=2)

    summary = (
        f"✅ {region} Batch (1/{batch_count}) Completed\n"
        f"🔹 Tokens Saved: {len(tokens)}\n"
        f"📂 Output: {output_file}"
    )
    print(summary)
    send_telegram_message(summary)

async def main():
    for region in REGION_CONFIG.keys():
        await generate_tokens_for_region(region)

if __name__ == "__main__":
    send_telegram_message("🤖 Multi-Region Token Generation Started...⚙️")
    asyncio.run(main())
    send_telegram_message("🤖 All Regions Completed!")

    if detect_git_conflict():
        resolve_git_conflict()

    push_to_git()
