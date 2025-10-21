import json, os, requests, asyncio
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, Bot, InputMediaPhoto
from telegram.ext import (
    ApplicationBuilder, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes
)

# ========== GLOBAL VARIABLES ==========
USER_DATA_FILE = "users_data.json"
DATA_FILE = "king_accounts.json"
USERS = {}
WAITING_FOR_INPUT = {}
USER_MINING_ACCOUNTS = {}
USER_PAGE = {}
WAITING_FOR_MINING_INPUT = {}

# ========== GAMES CONFIGURATION ==========
BOT_TOKEN = ""
FIREBASE_API_KEY_2 = 'AIzaSyCQDz9rgjgmvmFkvVfmvr2-7fT4tfrzRRQ'
FIREBASE_API_KEY_1 = 'AIzaSyBW1ZbMiUeDZHYUO2bY8Bfnf5rRgrQGPTM'
FIREBASE_LOGIN_URL_CPM2 = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={FIREBASE_API_KEY_2}"
FIREBASE_LOGIN_URL_CPM1 = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={FIREBASE_API_KEY_1}"
RANK_URL_CPM2 = "https://us-central1-cpm-2-7cea1.cloudfunctions.net/SetUserRating17_AppI"
RANK_URL_CPM1 = "https://us-central1-cp-multiplayer.cloudfunctions.net/SetUserRating4"
OWNER_ID = 6614066633
BOT_TOKEN = "8388427323:AAGbHsH4gd34BHIQp8kTxv-vcftN1aWEAiY"

# ========== IMAGE SETTINGS ==========
WELCOME_IMAGE_URL = "https://i.supaimg.com/81cef6f5-d12d-4c82-8c8f-2b29f4f32cb2.png"

# ========== Page Settings ==========
ACCOUNTS_PER_PAGE = 10
MAX_ACCOUNTS = 100

# ========== UTILITY FUNCTIONS ==========
def login1(email, password):
    payload = {
        "clientType": "CLIENT_TYPE_ANDROID",
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12)",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(FIREBASE_LOGIN_URL_CPM1, headers=headers, json=payload, timeout=10)
        response_data = response.json()

        if response.status_code == 200 and 'idToken' in response_data:
            return response_data.get('idToken'), None
        else:
            error_message = "Invalid credentials"
            if 'error' in response_data:
                error_code = response_data['error'].get('message', '')
                if error_code == 'INVALID_PASSWORD':
                    error_message = "Invalid Password"
                elif error_code == 'EMAIL_NOT_FOUND':
                    error_message = "Invalid Email"
                elif error_code == 'INVALID_EMAIL':
                    error_message = "Invalid Email Format"
                elif error_code == 'USER_DISABLED':
                    error_message = "Account Disabled"
                elif error_code == 'TOO_MANY_ATTEMPTS_TRY_LATER':
                    error_message = "Too Many Attempts, Try Later"
                else:
                    error_message = f"Login Error: {error_code}"
            
            print(f"Login1 failed: {error_message}")
            return None, error_message
    except Exception as e:
        error_msg = f"Connection Error: {e}"
        print(f"Login1 error: {e}")
        return None, error_msg

def login2(email, password):
    payload = {
        "clientType": "CLIENT_TYPE_ANDROID", 
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12)",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(FIREBASE_LOGIN_URL_CPM2, headers=headers, json=payload, timeout=10)
        response_data = response.json()

        if response.status_code == 200 and 'idToken' in response_data:
            return response_data.get('idToken'), None
        else:
            error_message = "Invalid credentials"
            if 'error' in response_data:
                error_code = response_data['error'].get('message', '')
                if error_code == 'INVALID_PASSWORD':
                    error_message = "Invalid Password"
                elif error_code == 'EMAIL_NOT_FOUND':
                    error_message = "Invalid Email"
                elif error_code == 'INVALID_EMAIL':
                    error_message = "Invalid Email Format"
                elif error_code == 'USER_DISABLED':
                    error_message = "Account Disabled"
                elif error_code == 'TOO_MANY_ATTEMPTS_TRY_LATER':
                    error_message = "Too Many Attempts, Try Later"
                else:
                    error_message = f"Login Error: {error_code}"
            
            print(f"Login2 failed: {error_message}")
            return None, error_message
    except Exception as e:
        error_msg = f"Connection Error: {e}"
        print(f"Login2 error: {e}")
        return None, error_msg

def set_rank1(token):
    rating_data = {k: 100000 for k in [
        "cars", "car_fix", "car_collided", "car_exchange", "car_trade", "car_wash",
        "slicer_cut", "drift_max", "drift", "cargo", "delivery", "taxi", "levels", "gifts", 
        "fuel", "offroad", "speed_banner", "reactions", "police", "run", "real_estate",
        "t_distance", "treasure", "block_post", "push_ups", "burnt_tire", "passanger_distance"
    ]}
    rating_data["time"] = 10000000000
    rating_data["race_win"] = 3000

    payload = {"data": json.dumps({"RatingData": rating_data})}
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json", 
        "User-Agent": "okhttp/3.12.13"
    }

    try:
        response = requests.post(RANK_URL_CPM1, headers=headers, json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Set rank1 error: {e}")
        return False

def set_rank2(token):
    rating_data = {k: 100000 for k in [
        "cars", "car_fix", "car_collided", "car_exchange", "car_trade", "car_wash",
        "slicer_cut", "drift_max", "drift", "cargo", "delivery", "taxi", "levels", "gifts",
        "fuel", "offroad", "speed_banner", "reactions", "police", "run", "real_estate", 
        "t_distance", "treasure", "block_post", "push_ups", "burnt_tire", "passanger_distance"
    ]}
    rating_data["time"] = 10000000000
    rating_data["race_win"] = 3000

    payload = {"data": json.dumps({"RatingData": rating_data})}
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "okhttp/3.12.13"
    }

    try:
        response = requests.post(RANK_URL_CPM2, headers=headers, json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Set rank2 error: {e}")
        return False

def load_users():
    global USERS
    if os.path.exists(USER_DATA_FILE):
        try:
            with open(USER_DATA_FILE, "r", encoding="utf-8") as f:
                USERS = json.load(f)
            print("✅ User data loaded successfully.")
        except (json.JSONDecodeError, Exception) as e:
            print(f"⚠️ users_data.json is corrupted or error: {e}. Starting with an empty database.")
            USERS = {}
    else:
        USERS = {}

def save_users():
    try:
        with open(USER_DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(USERS, f, indent=4, ensure_ascii=False)
        print("✅ User data saved successfully.")
    except Exception as e:
        print(f"⚠️ Failed to save user data: {e}")

def is_vip(user_id):
    user_id_str = str(user_id)
    if user_id_str in USERS:
        return USERS[user_id_str].get("slots", 0) > 0
    return False

def is_blocked(user_id):
    user_id_str = str(user_id)
    if user_id_str in USERS:
        return USERS[user_id_str].get("blocked", False)
    return False

def format_balance(balance):
    if balance >= 1000000000:
        return "♾️ Unlimited"
    else:
        return f"{balance:,} points"

# ========== ADMIN COMMANDS ==========
async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    
    if user.id != OWNER_ID:
        return
    
    admin_commands_text = (
        "🟥 WELCOME ADMIN HERE'S ALL ADMIN COMMAND :\n"
        "/check\n"
        "/add_balance\n" 
        "/remove_balance\n"
        "/give_rank\n"
        "/check_rank\n"
        "/remove_rank\n"
        "/block"
    )
    
    await update.message.reply_text(admin_commands_text)

async def give_rank_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    
    if user.id != OWNER_ID:
        await update.message.reply_text("🚫 You are not authorized to use this command.")
        return
    
    if len(context.args) != 2:
        await update.message.reply_text("❌ Usage: /give_rank <user_id> <slots_count>")
        return
    
    try:
        target_user_id = str(context.args[0])
        slots_count = int(context.args[1])
        
        if target_user_id not in USERS:
            await update.message.reply_text("❌ User not found in database.")
            return
        
        USERS[target_user_id]["slots"] = slots_count
        save_users()
        
        await update.message.reply_text(
            f"✅ VIP rank given successfully!\n"
            f"👤 User: {target_user_id}\n"
            f"🎰 Slots: {slots_count}\n"
            f"👑 VIP Status: ✅ Activated"
        )
        
        try:
            await context.bot.send_message(
                chat_id=target_user_id,
                text=f"🎉 Congratulations! You received VIP rank!\n🎰 Slots: {slots_count}\n👑 You can now use Coins Mining!"
            )
        except Exception as e:
            print(f"Failed to notify user: {e}")
            
    except ValueError:
        await update.message.reply_text("❌ Invalid slots count. Please enter a valid number.")

async def remove_rank_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    
    if user.id != OWNER_ID:
        await update.message.reply_text("🚫 You are not authorized to use this command.")
        return
    
    if len(context.args) != 1:
        await update.message.reply_text("❌ Usage: /remove_rank <user_id>")
        return
    
    target_user_id = str(context.args[0])
    
    if target_user_id not in USERS:
        await update.message.reply_text("❌ User not found in database.")
        return
    
    USERS[target_user_id]["slots"] = 0
    save_users()
    
    await update.message.reply_text(
        f"✅ VIP rank removed successfully!\n"
        f"👤 User: {target_user_id}\n"
        f"👑 VIP Status: ❌ Deactivated"
    )
    
    try:
        await context.bot.send_message(
            chat_id=target_user_id,
            text="⚠️ Your VIP rank has been removed by admin."
        )
    except Exception as e:
        print(f"Failed to notify user: {e}")

async def check_rank_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    
    if user.id != OWNER_ID:
        await update.message.reply_text("🚫 You are not authorized to use this command.")
        return
    
    vip_users = []
    for user_id, user_data in USERS.items():
        if user_data.get("slots", 0) > 0:
            vip_users.append((user_id, user_data))
    
    if not vip_users:
        await update.message.reply_text("📭 No VIP users found.")
        return
    
    text = "👑 VIP Users List:\n\n"
    for i, (user_id, user_data) in enumerate(vip_users, 1):
        text += f"{i}. 🆔 {user_id}\n"
        text += f"   👤 {user_data.get('name', 'N/A')}\n"
        text += f"   📱 @{user_data.get('username', 'N/A')}\n"
        text += f"   🎰 Slots: {user_data.get('slots', 0)}\n"
        text += f"   💰 Balance: {format_balance(user_data.get('balance', 0))}\n\n"
    
    await update.message.reply_text(text)

async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    
    if user.id != OWNER_ID:
        await update.message.reply_text("🚫 You are not authorized to use this command.")
        return
    
    if len(context.args) != 1:
        await update.message.reply_text("❌ Usage: /check <user_id>")
        return
    
    target_user_id = str(context.args[0])
    
    if target_user_id not in USERS:
        await update.message.reply_text("❌ User not found in database.")
        return
    
    user_data = USERS[target_user_id]
    blocked_status = "✅ Yes" if user_data.get("blocked", False) else "❌ No"
    free_trial_used = "✅ Yes" if user_data.get("free_trial_used", False) else "❌ No"
    vip_status = "✅ VIP" if is_vip(target_user_id) else "❌ Not VIP"
    
    text = (
        f"👑 Welcome {user_data.get('name', 'N/A')} HERE'S YOUR ACCOUNT INFO 👇:\n\n"
        f"🆔 Telegram ID: {target_user_id}\n"
        f"💰 Balance: {format_balance(user_data.get('balance', 0))} Credits\n"
        f"🎰 Slots: {user_data.get('slots', 0)}\n"
        f"👑 VIP Status: {vip_status}\n"
        f"🚫 Blocked: {blocked_status}\n"
        f"🎁 Free Trial Used: {free_trial_used}\n"
        f"📅 Registered: {user_data.get('registered_at', 'N/A')}"
    )
    
    await update.message.reply_text(text)

async def block_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    
    if user.id != OWNER_ID:
        await update.message.reply_text("🚫 You are not authorized to use this command.")
        return
    
    if len(context.args) != 2:
        await update.message.reply_text("❌ Usage: /block <user_id> <block/unblock>")
        return
    
    target_user_id = str(context.args[0])
    action = context.args[1].lower()
    
    if target_user_id not in USERS:
        await update.message.reply_text("❌ User not found in database.")
        return
    
    if action == "block":
        USERS[target_user_id]["blocked"] = True
        save_users()
        await update.message.reply_text(f"✅ User {target_user_id} has been blocked.")
        
        try:
            await context.bot.send_message(
                chat_id=target_user_id,
                text="🚫 You have been blocked from using this bot."
            )
        except Exception as e:
            print(f"Failed to notify user: {e}")
            
    elif action == "unblock":
        USERS[target_user_id]["blocked"] = False
        save_users()
        await update.message.reply_text(f"✅ User {target_user_id} has been unblocked.")
        
        try:
            await context.bot.send_message(
                chat_id=target_user_id,
                text="✅ You have been unblocked and can now use the bot again."
            )
        except Exception as e:
            print(f"Failed to notify user: {e}")
    else:
        await update.message.reply_text("❌ Invalid action. Use 'block' or 'unblock'.")

async def add_balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    
    if user.id != OWNER_ID:
        await update.message.reply_text("🚫 You are not authorized to use this command.")
        return
    
    if len(context.args) != 2:
        await update.message.reply_text("❌ Usage: /add_balance <user_id> <amount>")
        return
    
    try:
        target_user_id = str(context.args[0])
        amount = int(context.args[1])
        
        if target_user_id not in USERS:
            await update.message.reply_text("❌ User not found in database.")
            return
        
        USERS[target_user_id]["balance"] += amount
        save_users()
        
        await update.message.reply_text(
            f"✅ Successfully added {amount:,} points to user {target_user_id}\n"
            f"💰 New balance: {format_balance(USERS[target_user_id]['balance'])}"
        )
        
        try:
            await context.bot.send_message(
                chat_id=target_user_id,
                text=f"🎉 You received {amount:,} points from admin!\n💰 Your new balance: {format_balance(USERS[target_user_id]['balance'])}"
            )
        except Exception as e:
            print(f"Failed to notify user: {e}")
            
    except ValueError:
        await update.message.reply_text("❌ Invalid amount. Please enter a valid number.")

async def remove_balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    
    if user.id != OWNER_ID:
        await update.message.reply_text("🚫 You are not authorized to use this command.")
        return
    
    if len(context.args) != 2:
        await update.message.reply_text("❌ Usage: /remove_balance <user_id> <amount>")
        return
    
    try:
        target_user_id = str(context.args[0])
        amount = int(context.args[1])
        
        if target_user_id not in USERS:
            await update.message.reply_text("❌ User not found in database.")
            return
        
        if USERS[target_user_id]["balance"] < amount:
            await update.message.reply_text("❌ User doesn't have enough balance.")
            return
        
        USERS[target_user_id]["balance"] -= amount
        save_users()
        
        await update.message.reply_text(
            f"✅ Successfully removed {amount:,} points from user {target_user_id}\n"
            f"💰 New balance: {format_balance(USERS[target_user_id]['balance'])}"
        )
        
        try:
            await context.bot.send_message(
                chat_id=target_user_id,
                text=f"⚠️ {amount:,} points were removed from your balance by admin.\n💰 Your new balance: {format_balance(USERS[target_user_id]['balance'])}"
            )
        except Exception as e:
            print(f"Failed to notify user: {e}")
            
    except ValueError:
        await update.message.reply_text("❌ Invalid amount. Please enter a valid number.")

# ========== USER COMMANDS ==========
async def free_trial_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    uid = str(user.id)
    
    if uid not in USERS:
        USERS[uid] = {
            "name": user.full_name or "No name",
            "username": user.username or "No username",
            "balance": 0,
            "slots": 0,
            "registered_at": datetime.utcnow().isoformat(),
            "free_trial_used": False,
            "blocked": False
        }
    
    if is_blocked(uid):
        await update.message.reply_text("🚫 You are blocked from using this bot.")
        return
    
    if USERS[uid].get("free_trial_used", False):
        await update.message.reply_text("❌ You have already used your free trial.")
        return
    
    USERS[uid]["balance"] += 15000
    USERS[uid]["free_trial_used"] = True
    save_users()
    
    await update.message.reply_text(
        "🎉 Congratulations! You received 15,000 free points!\n\n"
        f"💰 Your new balance: {format_balance(USERS[uid]['balance'])}"
    )

async def balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    uid = str(user.id)
    
    if is_blocked(uid):
        await update.message.reply_text("🚫 You are blocked from using this bot.")
        return
    
    if uid not in USERS:
        USERS[uid] = {
            "name": user.full_name or "No name",
            "username": user.username or "No username",
            "balance": 0,
            "slots": 0,
            "registered_at": datetime.utcnow().isoformat(),
            "free_trial_used": False,
            "blocked": False
        }
        save_users()
    
    vip_status = "✅ VIP" if is_vip(uid) else "❌ Not VIP"
    blocked_status = "🚫 Yes" if is_blocked(uid) else "✅ No"
    balance = USERS[uid]["balance"]
    
    text = (
        f"💰 Your Balance Information:\n\n"
        f"👤 User: {user.first_name}\n"
        f"🆔 ID: {uid}\n"
        f"💳 Balance: {format_balance(balance)}\n"
        f"🎰 Slots: {USERS[uid]['slots']}\n"
        f"👑 VIP Status: {vip_status}\n"
        f"🚫 Blocked: {blocked_status}"
    )
    
    await update.message.reply_text(text)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    uid = str(user.id)

    if is_blocked(uid):
        await update.message.reply_text("🚫 You are blocked from using this bot.")
        return

    if uid not in USERS:
        USERS[uid] = {
            "name": user.full_name or "No name",
            "username": user.username or "No username",
            "balance": 0,
            "slots": 0,
            "registered_at": datetime.utcnow().isoformat(),
            "free_trial_used": False,
            "blocked": False
        }
        save_users()

    args = context.args
    if args:
        ref_code = args[0]
        if ref_code.startswith("ref_"):
            inviter_id = ref_code.replace("ref_", "")
            
            if "invited_from" not in USERS[uid]:
                USERS[uid]["invited_from"] = inviter_id
                
                if inviter_id in USERS:
                    USERS[inviter_id]["balance"] += 5000
                    try:
                        await context.bot.send_message(
                            chat_id=int(inviter_id),
                            text=f"🎉 You received 5000 bonus points!\n👤 {user.first_name} joined using your invite link!\n💰 Your new balance: {format_balance(USERS[inviter_id]['balance'])}"
                        )
                    except Exception as e:
                        print(f"Failed to notify inviter: {e}")
                
                USERS[uid]["balance"] += 5000
                save_users()
                
                await update.message.reply_text(
                    "🎁 You received 5000 bonus points for joining via invite link!"
                )

    vip_status = "✅ VIP" if is_vip(uid) else "❌ Not VIP"
    blocked_status = "🚫 Yes" if is_blocked(uid) else "✅ No"
    
    keyboard = [
        [InlineKeyboardButton("👑 King Rank", callback_data="king_rank")],
        [
            InlineKeyboardButton("⛏️ Coins Mining", callback_data="autotasks_cpm2"),
            InlineKeyboardButton("💳 Buy Credit", callback_data="buy_credit"),
        ],
        [
            InlineKeyboardButton("📣 Invite Friends", callback_data="invite_friends"),
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    text = (
        f"👋 Welcome {user.first_name} to the Tool CPM 1 & 2 Bot!\n\n"
        f"🧑‍🏫 Owner: @rayaninho_1\n"
        f"📢 Channel: @soon\n"
        f"🔓 Group: @soon\n\n"
        f"👤 Your ID: {uid}\n"
        f"🎰 Slots: {USERS[uid]['slots']}\n"
        f"💰 Your Balance: {format_balance(USERS[uid]['balance'])}\n"
        f"👑 Status: {vip_status}\n"
        f"🚫 Blocked: {blocked_status}"
    )

    try:
        await update.message.reply_photo(
            photo=WELCOME_IMAGE_URL,
            caption=text,
            reply_markup=reply_markup
        )
        print(f"✅ Photo sent successfully to user {uid}")
    except Exception as e:
        print(f"❌ Error sending photo: {e}")
        await update.message.reply_text(text, reply_markup=reply_markup)
    
    save_users()

# ========== HELPER FUNCTIONS ==========
async def safe_edit_message(query, text, reply_markup=None):
    try:
        await query.edit_message_text(text, reply_markup=reply_markup, parse_mode="Markdown")
        print("✅ Message edited successfully (text)")
    except Exception as e:
        try:
            await query.edit_message_caption(caption=text, reply_markup=reply_markup, parse_mode="Markdown")
            print("✅ Message edited successfully (caption)")
        except Exception as e2:
            print(f"❌ Failed to edit message: {e2}")
            await query.message.reply_text(text, reply_markup=reply_markup, parse_mode="Markdown")
            print("✅ New message sent instead")

# ========== ALL BUTTONS HANDLER ==========
async def handle_all_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data
    user = query.from_user
    uid = str(user.id)
    await query.answer()

    if is_blocked(uid):
        await safe_edit_message(query, "🚫 You are blocked from using this bot.")
        return

    print(f"🔍 Button pressed: {data} by user {uid}")

    # Main menu buttons
    if data == "king_rank":
        text = (
            "👑 Choose your rank-related option:\n\n"
            "────────────────────\n"
            "🔻 Rank King CPM 1 – Instantly upgrades your account to the highest rank available, Instantly completes the daily task.\n\n"
            "🔻 Rank King CPM 2 +(300 Coins) – Instantly completes the daily task and credits your account with 300 coins.\n\n"
            "────────────────────\n"
            "💳 Each option costs 5,000 credits.\n"
            "⚡ Quick, safe, and automatic activation.\n\n"
            "📌 Tap a button below to proceed:"
        )
        
        kb = [
            [InlineKeyboardButton("👑 Rank King CPM 1", callback_data="kingrank_cpm1")],
            [InlineKeyboardButton("👑 Rank King CPM 2 + 300 Coins", callback_data="kingrank_cpm2")],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")],
        ]
        
        await safe_edit_message(query, text, InlineKeyboardMarkup(kb))
    
    elif data == "kingrank_cpm1":
        balance = USERS.get(uid, {}).get("balance", 0)

        if balance < 5000:
            msg = (
                f"⚠️ Not enough balance.\n"
                f"💰 Your balance: {format_balance(balance)}\n"
                f"💳 Required: 5,000"
            )
            await query.message.reply_text(msg)
            return
    
        await query.message.reply_text("📧 Please enter your email:")
        WAITING_FOR_INPUT[user.id] = {"step": "email", "type": data}
    
    elif data == "kingrank_cpm2":
        balance = USERS.get(uid, {}).get("balance", 0)
    
        if balance < 5000:
            msg = (
                f"⚠️ Not enough balance.\n"
                f"💰 Your balance: {format_balance(balance)}\n"
                f"💳 Required: 5,000"
            )
            await query.message.reply_text(msg)
            return

        await query.message.reply_text("📧 Please enter your email:")
        WAITING_FOR_INPUT[user.id] = {"step": "email", "type": data}
        
    elif data == "back_to_main":
        await start_from_query(update, context)
        
    elif data == "autotasks_cpm2":
        if not is_vip(uid):
            await safe_edit_message(
                query,
                "⛔ You don't have any slots yet to buy slots and start mining coins contact\n@rayaninho_1",
                InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]])
            )
            return
        
        try:
            await coins_mining_menu(update, context, page=0)
        except Exception as e:
            print(f"❌ Error opening mining menu: {e}")
            await safe_edit_message(
                query,
                "❌ Error opening mining menu. Please try again.",
                InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]])
            )
        
    elif data == "buy_credit":
        text = (
            "💳 *BUY CREDIT*\n\n"
            "To purchase credit, contact the owner directly:\n"
            "👤 @rayaninho_1\n\n"
            "Click the button below to start a conversation."
        )
    
        keyboard = [
            [InlineKeyboardButton("💬 Contact @rayaninho_1", url="https://t.me/rayaninho_1")],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
    
        await safe_edit_message(query, text, reply_markup)
        
    elif data == "invite_friends":
        await invite_friends(update, context)
    
    # Mining buttons
    elif data.startswith("delete_acc_"):
        email = data.replace("delete_acc_", "")
        print(f"🗑️ Deleting account: {email}")
        
        if uid in USER_MINING_ACCOUNTS:
            original_count = len(USER_MINING_ACCOUNTS[uid])
            USER_MINING_ACCOUNTS[uid] = [acc for acc in USER_MINING_ACCOUNTS[uid] if acc["email"] != email]
            new_count = len(USER_MINING_ACCOUNTS[uid])
            
            if new_count < original_count:
                save_data()
                await query.answer(f"✅ Account deleted successfully!", show_alert=True)
                current_page = USER_PAGE.get(uid, 0)
                await coins_mining_menu(update, context, page=current_page)
            else:
                await query.answer("❌ Account not found!", show_alert=True)
                current_page = USER_PAGE.get(uid, 0)
                await coins_mining_menu(update, context, page=current_page)
        else:
            await query.answer("❌ No accounts found!", show_alert=True)
            current_page = USER_PAGE.get(uid, 0)
            await coins_mining_menu(update, context, page=current_page)

    elif data.startswith("view_acc_"):
        email = data.replace("view_acc_", "")
        print(f"👀 Viewing account: {email}")
        
        account = None
        account_number = 0
        
        if uid in USER_MINING_ACCOUNTS:
            for i, acc in enumerate(USER_MINING_ACCOUNTS[uid]):
                if acc["email"] == email:
                    account = acc
                    account_number = i + 1
                    break
        
        if account:
            added_date = account.get('added_at', 'Unknown')
            if added_date != 'Unknown':
                try:
                    added_date = datetime.fromisoformat(added_date).strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            text = (
                f"🔐 *ACCOUNT INFORMATION* ({account_number})\n\n"
                f"📧 *Email:* `{account['email']}`\n"
                f"🔒 *Password:* `{account['password']}`\n"
                f"📅 *Added:* {added_date}\n\n"
                f"⚡ *Status:* ✅ Active"
            )
            
            current_page = USER_PAGE.get(uid, 0)
            keyboard = [[InlineKeyboardButton("🔙 Back to Accounts", callback_data=f"page_{current_page}")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await safe_edit_message(query, text, reply_markup)
        else:
            await query.answer("❌ Account not found!", show_alert=True)
    
    elif data.startswith("page_"):
        page_num = int(data.replace("page_", ""))
        print(f"📄 Changing to page: {page_num}")
        await coins_mining_menu(update, context, page=page_num)
    
    elif data == "add_new_account":
        print(f"➕ Adding new account")
        if not is_vip(uid):
            await safe_edit_message(
                query,
                "❌ You don't have any available slots! Contact @rayaninho_1 to buy slots."
            )
            return

        accounts_count = len(USER_MINING_ACCOUNTS.get(uid, []))
        available_slots = USERS[uid].get("slots", 0)
        
        if accounts_count >= available_slots:
            await safe_edit_message(
                query,
                f"❌ You have reached your slots limit!\n"
                f"📊 Current: {accounts_count}/{available_slots} accounts\n"
                f"💡 Contact @rayaninho_1 to buy more slots"
            )
            return

        if accounts_count >= MAX_ACCOUNTS:
            await safe_edit_message(query, f"❌ You have reached the maximum limit of {MAX_ACCOUNTS} accounts.")
            return
        
        await safe_edit_message(query, "📧 Enter your account email:")
        WAITING_FOR_MINING_INPUT[uid] = {"step": "email"}

    elif data == "slot_full":
        await query.answer("❌ This slot is full! Delete an account to free up space.", show_alert=True)

async def start_from_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user = query.from_user
    uid = str(user.id)

    if is_blocked(uid):
        await safe_edit_message(query, "🚫 You are blocked from using this bot.")
        return

    if uid not in USERS:
        USERS[uid] = {
            "name": user.full_name or "No name",
            "username": user.username or "No username",
            "balance": 0,
            "slots": 0,
            "registered_at": datetime.utcnow().isoformat(),
            "free_trial_used": False,
            "blocked": False
        }
        save_users()

    vip_status = "✅ VIP" if is_vip(uid) else "❌ Not VIP"
    blocked_status = "🚫 Yes" if is_blocked(uid) else "✅ No"
    
    keyboard = [
        [InlineKeyboardButton("👑 King Rank", callback_data="king_rank")],
        [
            InlineKeyboardButton("⛏️ Coins Mining", callback_data="autotasks_cpm2"),
            InlineKeyboardButton("💳 Buy Credit", callback_data="buy_credit"),
        ],
        [
            InlineKeyboardButton("📣 Invite Friends", callback_data="invite_friends"),
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    text = (
        f"👋 Welcome {user.first_name} to the Tool CPM 1 & 2 Bot!\n\n"
        f"🧑‍🏫 Owner: @rayaninho_1\n"
        f"📢 Channel: @soon\n"
        f"🔓 Group: @soon\n\n"
        f"👤 Your ID: {uid}\n"
        f"🎰 Slots: {USERS[uid]['slots']}\n"
        f"💰 Your Balance: {format_balance(USERS[uid]['balance'])}\n"
        f"👑 Status: {vip_status}\n"
        f"🚫 Blocked: {blocked_status}"
    )

    try:
        await query.edit_message_media(
            media=InputMediaPhoto(media=WELCOME_IMAGE_URL, caption=text),
            reply_markup=reply_markup
        )
        print(f"✅ Photo updated successfully for user {uid}")
    except Exception as e:
        print(f"❌ Error updating photo: {e}")
        await safe_edit_message(query, text, reply_markup)
    
    save_users()

# ========== MESSAGE HANDLERS ==========
async def handle_user_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    text = update.message.text
    uid = user.id
    str_uid = str(uid)

    if is_blocked(str_uid):
        await update.message.reply_text("🚫 You are blocked from using this bot.")
        return

    if str_uid in WAITING_FOR_MINING_INPUT:
        await handle_mining_input(update, context)
        return

    if uid not in WAITING_FOR_INPUT:
        await update.message.reply_text("🤖 Please use the menu buttons.")
        return

    user_state = WAITING_FOR_INPUT[uid]

    if user_state["step"] == "email":
        user_state["email"] = text
        user_state["step"] = "password"
        await update.message.reply_text("🔐 Now enter your password:")

    elif user_state["step"] == "password":
        email = user_state.get("email")
        password = text
        rank_type = user_state.get("type")

        await update.message.reply_text("⏳ Logging in... please wait.")
        
        if rank_type == "kingrank_cpm1":
            token, error_msg = login1(email, password)
        else:
            token, error_msg = login2(email, password)

        if not token:
            await update.message.reply_text(f"❌ Login Failed. {error_msg}")
            WAITING_FOR_INPUT.pop(uid, None)
            return

        if rank_type == "kingrank_cpm1":
            success = set_rank1(token)
        else:
            success = set_rank2(token)
            
        if success:
            USERS[str_uid]["balance"] -= 5000
            new_balance = USERS[str_uid]["balance"]
            save_users()

            await update.message.reply_text(
                f"✅ {rank_type.upper()} successfully activated!\n"
                f"💳 5,000 points have been deducted.\n"
                f"💰 Your new balance: {format_balance(new_balance)}"
            )
        else:
            await update.message.reply_text("❌ Failed to activate rank. Try again later.")

        WAITING_FOR_INPUT.pop(uid, None)

# ========== MINING SYSTEM ==========
def load_data():
    global USER_MINING_ACCOUNTS
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                USER_MINING_ACCOUNTS = json.load(f)
            print("✅ Mining accounts data loaded successfully.")
        except (json.JSONDecodeError, Exception) as e:
            print(f"⚠️ {DATA_FILE} is corrupted or error: {e}. Starting with empty mining accounts.")
            USER_MINING_ACCOUNTS = {}
    else:
        USER_MINING_ACCOUNTS = {}

def save_data():
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(USER_MINING_ACCOUNTS, f, indent=4, ensure_ascii=False)
        print("✅ Mining accounts data saved successfully.")
    except Exception as e:
        print(f"⚠️ Failed to save mining accounts data: {e}")

async def handle_mining_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    text = update.message.text.strip()

    if is_blocked(uid):
        await update.message.reply_text("🚫 You are blocked from using this bot.")
        return

    if uid not in WAITING_FOR_MINING_INPUT:
        return

    state = WAITING_FOR_MINING_INPUT[uid]

    if state["step"] == "email":
        if not is_vip(uid):
            await update.message.reply_text("❌ You don't have any available slots!")
            WAITING_FOR_MINING_INPUT.pop(uid, None)
            return

        current_accounts = len(USER_MINING_ACCOUNTS.get(uid, []))
        available_slots = USERS[uid].get("slots", 0)
        
        if current_accounts >= available_slots:
            await update.message.reply_text(f"❌ You have reached your maximum slots limit ({available_slots})!")
            WAITING_FOR_MINING_INPUT.pop(uid, None)
            return

        email = text.lower()

        accounts_count = len(USER_MINING_ACCOUNTS.get(uid, []))
        if accounts_count >= MAX_ACCOUNTS:
            await update.message.reply_text(f"❌ You have reached the maximum limit of {MAX_ACCOUNTS} accounts.")
            WAITING_FOR_MINING_INPUT.pop(uid, None)
            return

        for acc in USER_MINING_ACCOUNTS.get(uid, []):
            if acc["email"] == email:
                await update.message.reply_text(f"⚠️ `{email}` already exists!", parse_mode="Markdown")
                WAITING_FOR_MINING_INPUT.pop(uid, None)
                return

        state["email"] = email
        state["step"] = "password"
        await update.message.reply_text("🔐 Enter your password:")

    elif state["step"] == "password":
        email = state["email"]
        password = text

        await update.message.reply_text("⏳ Verifying account...")
        token, error_msg = login2(email, password)
        if not token:
            await update.message.reply_text(f"❌ Login Failed. {error_msg}")
            WAITING_FOR_MINING_INPUT.pop(uid, None)
            return

        USER_MINING_ACCOUNTS.setdefault(uid, []).append({
            "email": email,
            "password": password,
            "added_at": datetime.utcnow().isoformat()
        })
        save_data()

        current_accounts = len(USER_MINING_ACCOUNTS[uid])
        available_slots = USERS[uid].get("slots", 0)
        remaining_slots = available_slots - current_accounts

        await update.message.reply_text(
            f"✅ Account `{email}` added successfully!\n\n"
            f"📊 Account Statistics:\n"
            f"• Total accounts: {current_accounts}/{MAX_ACCOUNTS}\n"
            f"• Available slots: {remaining_slots}/{available_slots}",
            parse_mode="Markdown"
        )
        WAITING_FOR_MINING_INPUT.pop(uid, None)
        
        current_page = USER_PAGE.get(uid, 0)
        try:
            await coins_mining_menu_from_message(update, context, page=current_page)
        except Exception as e:
            print(f"Error returning to mining menu: {e}")

def build_mining_keyboard(uid: str, current_page: int, total_pages: int, accounts: list, available_slots: int, total_accounts: int):
    keyboard = []
    
    for i, acc in enumerate(accounts, start=current_page * ACCOUNTS_PER_PAGE + 1):
        keyboard.append([
            InlineKeyboardButton(f"Account {i} ✅", callback_data=f"view_acc_{acc['email']}"),
            InlineKeyboardButton("🗑️ Delete", callback_data=f"delete_acc_{acc['email']}")
        ])
    
    remaining_on_page = ACCOUNTS_PER_PAGE - len(accounts)
    next_account_num = len(accounts) + 1 + (current_page * ACCOUNTS_PER_PAGE)
    
    for i in range(remaining_on_page):
        if total_accounts < available_slots and total_accounts < MAX_ACCOUNTS:
            keyboard.append([
                InlineKeyboardButton(f"➕ Add Account {next_account_num}", callback_data="add_new_account")
            ])
            next_account_num += 1
        else:
            keyboard.append([
                InlineKeyboardButton(f"❌ Slot {next_account_num} (Full)", callback_data="slot_full")
            ])
            next_account_num += 1
    
    navigation_buttons = []
    
    if current_page > 0:
        navigation_buttons.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"page_{current_page - 1}"))
    
    if total_pages > 1:
        navigation_buttons.append(InlineKeyboardButton(f"Page {current_page + 1}/{total_pages}", callback_data="current_page"))
    
    if current_page < total_pages - 1 and total_pages > 1:
        navigation_buttons.append(InlineKeyboardButton("Next ➡️", callback_data=f"page_{current_page + 1}"))
    
    if navigation_buttons:
        keyboard.append(navigation_buttons)

    keyboard.append([InlineKeyboardButton("🔙 Back to Main", callback_data="back_to_main")])
    
    return InlineKeyboardMarkup(keyboard)

async def coins_mining_menu(update: Update, context: ContextTypes.DEFAULT_TYPE, page: int = 0):
    query = update.callback_query
    uid = str(query.from_user.id)
    
    if not is_vip(uid):
        await safe_edit_message(
            query,
            "⛔ You don't have any slots yet to buy slots and start mining coins contact\n@rayaninho_1",
            InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]])
        )
        return
    
    await query.answer()

    if uid not in USER_MINING_ACCOUNTS:
        USER_MINING_ACCOUNTS[uid] = []
        save_data()

    accounts = USER_MINING_ACCOUNTS.get(uid, [])
    total_accounts = len(accounts)
    available_slots = USERS[uid].get("slots", 0)
    remaining_slots = max(0, available_slots - total_accounts)
    
    total_pages = max(1, (total_accounts + ACCOUNTS_PER_PAGE - 1) // ACCOUNTS_PER_PAGE)
    
    if page >= total_pages:
        page = 0
    
    USER_PAGE[uid] = page
    
    start_idx = page * ACCOUNTS_PER_PAGE
    end_idx = start_idx + ACCOUNTS_PER_PAGE
    current_page_accounts = accounts[start_idx:end_idx]
    
    markup = build_mining_keyboard(uid, page, total_pages, current_page_accounts, available_slots, total_accounts)
    
    text = (
        "⛏️ *COINS MINING MENU*\n"
        "────────────────────\n"
        "🔁 Auto Daily Task – Once you add your account, our system will automatically complete daily tasks for you.\n"
        "────────────────────\n\n"
        f"🔠 Select an account to manage (Page {page + 1}):\n\n"
    )
    
    if not current_page_accounts:
        text += "📭 No accounts added yet.\n\n"
    else:
        for i, acc in enumerate(current_page_accounts, start=start_idx + 1):
            text += f"• Account {i} ✅\n"
    
    text += f"\n📊 *Statistics:*\n"
    text += f"• Total Accounts: {total_accounts}/{available_slots}\n"
    text += f"• Available Slots: {remaining_slots}\n"
    text += f"• Maximum Limit: {MAX_ACCOUNTS} accounts"
    
    await safe_edit_message(query, text, markup)

async def coins_mining_menu_from_message(update: Update, context: ContextTypes.DEFAULT_TYPE, page: int = 0):
    uid = str(update.effective_user.id)

    if uid not in USER_MINING_ACCOUNTS:
        USER_MINING_ACCOUNTS[uid] = []
        save_data()

    accounts = USER_MINING_ACCOUNTS.get(uid, [])
    total_accounts = len(accounts)
    available_slots = USERS[uid].get("slots", 0)
    remaining_slots = max(0, available_slots - total_accounts)
    
    total_pages = max(1, (total_accounts + ACCOUNTS_PER_PAGE - 1) // ACCOUNTS_PER_PAGE)
    
    if page >= total_pages:
        page = 0
    
    USER_PAGE[uid] = page
    
    start_idx = page * ACCOUNTS_PER_PAGE
    end_idx = start_idx + ACCOUNTS_PER_PAGE
    current_page_accounts = accounts[start_idx:end_idx]
    
    markup = build_mining_keyboard(uid, page, total_pages, current_page_accounts, available_slots, total_accounts)
    
    text = (
        "⛏️ *COINS MINING MENU*\n"
        "────────────────────\n"
        "🔁 Auto Daily Task – Once you add your account, our system will automatically complete daily tasks for you.\n"
        "────────────────────\n\n"
        f"🔠 Select an account to manage (Page {page + 1}):\n\n"
    )
    
    if not current_page_accounts:
        text += "📭 No accounts added yet.\n\n"
    else:
        for i, acc in enumerate(current_page_accounts, start=start_idx + 1):
            text += f"• Account {i} ✅\n"
    
    text += f"\n📊 *Statistics:*\n"
    text += f"• Total Accounts: {total_accounts}/{available_slots}\n"
    text += f"• Available Slots: {remaining_slots}\n"
    text += f"• Maximum Limit: {MAX_ACCOUNTS} accounts"
    
    await update.message.reply_text(text, reply_markup=markup)

# ========== AUTOMATIC DAILY TASK ==========
def auto_king_rank_sync():
    print(f"\n🕒 Auto King Rank job running at {datetime.now()}")
    total, success, failed_login, failed_rank = 0, 0, 0, 0

    for uid, accs in USER_MINING_ACCOUNTS.items():
        for acc in accs:
            total += 1
            email = acc.get("email")
            password = acc.get("password")

            token, error_msg = login2(email, password)
            if not token:
                failed_login += 1
                msg = f"⚠️ Login failed for `{email}`\n🧾 Reason: {error_msg}"
                print(msg)
                continue

            ok = set_rank2(token)
            if ok:
                success += 1
            else:
                failed_rank += 1
            
            try:
                with open("kingrank_log.txt", "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now()} | {email} | {'OK' if ok else 'FAIL'}\n")
            except Exception as e:
                print(f"Failed to write log: {e}")

    print(f"👑 Auto King Rank done: total={total}, success={success}, failed_login={failed_login}, failed_rank={failed_rank}")

def start_scheduler():
    """بدء المجدول باستخدام threading"""
    import threading
    import time
    
    def scheduler_loop():
        while True:
            now = datetime.now()
            target_time = now.replace(hour=3, minute=0, second=0, microsecond=0)
            if now >= target_time:
                target_time = target_time.replace(day=target_time.day + 1)
            
            wait_seconds = (target_time - now).total_seconds()
            print(f"⏰ Next auto rank task in {wait_seconds:.0f} seconds ({wait_seconds/3600:.1f} hours)")
            
            time.sleep(wait_seconds)
            auto_king_rank_sync()
    
    scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
    scheduler_thread.start()
    print("✅ Auto King Rank scheduler started")

# ========== INVITE SYSTEM ==========
async def invite_friends(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    uid = str(query.from_user.id)
    await query.answer()

    bot_username = (await context.bot.get_me()).username
    invite_link = f"https://t.me/{bot_username}?start=ref_{uid}"

    text = (
        "🎁 *INVITE FRIENDS*\n\n"
        f"🔗 *Your invite link:*\n`{invite_link}`\n\n"
        "💰 *Rewards:*\n"
        "• You get 5000 points when someone joins using your link\n"
        "• Your friend also gets 5000 bonus points\n\n"
        "📈 Share your link and earn more points!"
    )

    keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]]
    
    await safe_edit_message(query, text, InlineKeyboardMarkup(keyboard))

# ========== INITIALIZATION ==========
def initialize():
    load_data()
    start_scheduler()
    print("✅ Auto King Rank system initialized")

# ========== ERROR HANDLER ==========
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"⚠️ Error occurred: {context.error}")
    
    if update and update.callback_query:
        try:
            await update.callback_query.answer("❌ An error occurred. Please try again.")
        except:
            pass

# ========== APPLICATION SETUP ==========
app = ApplicationBuilder().token(BOT_TOKEN).build()

# Add command handlers
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("balance", balance_command))
app.add_handler(CommandHandler("free_trial", free_trial_command))
app.add_handler(CommandHandler("add_balance", add_balance_command))
app.add_handler(CommandHandler("remove_balance", remove_balance_command))
app.add_handler(CommandHandler("admin", admin_command))
app.add_handler(CommandHandler("check", check_command))
app.add_handler(CommandHandler("block", block_command))
app.add_handler(CommandHandler("give_rank", give_rank_command))
app.add_handler(CommandHandler("remove_rank", remove_rank_command))
app.add_handler(CommandHandler("check_rank", check_rank_command))

# Add callback query handler
app.add_handler(CallbackQueryHandler(handle_all_buttons))

# Add message handler
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_user_message))

# Add error handler
app.add_error_handler(error_handler)

# ========== START THE BOT ==========
if __name__ == "__main__":
    load_users()
    load_data()
    initialize()
    
    print("🤖 Bot is starting...")

    try:
        app.run_polling()
    except KeyboardInterrupt:
        print("🛑 Bot stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        print("🔴 Bot shutdown complete")