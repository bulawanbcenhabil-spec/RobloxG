import os
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, render_template_string, send_file, session, redirect, url_for, jsonify
import aiohttp
import asyncio
import cachetools
import csv
import io
import time
import random
import threading
import smtplib
import re
import json
from email.mime.text import MIMEText
from collections import deque
import base64
import hashlib
from datetime import datetime

# Vercel-specific configuration
if os.environ.get('VERCEL'):
    CONFIG_FILE = "/tmp/config.json"
    HISTORY_FILE = "/tmp/history.json"
else:
    CONFIG_FILE = "config.json"
    HISTORY_FILE = "history.json"

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your_secret_key")

# Configuration
DEFAULT_CONFIG = {
    "webhook_url": os.getenv("WEBHOOK_URL", "https://webhook.lewisakura.moe/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN/queue"),
    "slack_url": os.getenv("SLACK_URL", ""),
    "telegram": {
        "enabled": os.getenv("TELEGRAM_ENABLED", "False") == "True",
        "bot_token": os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN"),
        "chat_id": os.getenv("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID")
    },
    "email": {
        "enabled": os.getenv("EMAIL_ENABLED", "False") == "True",
        "smtp_server": os.getenv("EMAIL_SMTP_SERVER", "smtp.gmail.com"),
        "smtp_port": int(os.getenv("EMAIL_SMTP_PORT", 587)),
        "sender_email": os.getenv("EMAIL_SENDER", "your_email@gmail.com"),
        "sender_password": os.getenv("EMAIL_PASSWORD", "your_app_password"),
        "receiver_email": os.getenv("EMAIL_RECEIVER", "your_email@gmail.com")
    },
    "admin_users": [
        {"username": "admin", "password": hashlib.sha256("admin123".encode()).hexdigest(), "role": "full"}
    ],
    "check_interval": 300,
    "webhook_rate": 10,
    "export_schedule": None,
    "notification_channels": {"discord": True, "telegram": False, "slack": False, "email": False},
    "dedup_window": 3600
}

# Try to load config, create if doesn't exist
try:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    else:
        config = DEFAULT_CONFIG
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
except:
    config = DEFAULT_CONFIG

PROXY_LIST_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"
DEFAULT_SEARCH_KEYWORDS = ["abandoned", "free", "old", "clan", "group"]
DEFAULT_MIN_MEMBERS = 10
DEFAULT_REGEX_PATTERN = r"^[a-zA-Z0-9]{3,5}$"
DEFAULT_MAX_RESULTS = 5
DEFAULT_ACTIVITY_DAYS = 30
DEFAULT_GROUP_ID_RANGE = (1, 1000)
DEFAULT_SCORE_WEIGHTS = {"members": 0.001, "name_length": 5.0}
DEFAULT_WEBHOOK_TEMPLATE = (
    "**High-Value Group Found via '{keyword}'! (Score: {score:.1f})**\n"
    "**Name**: {name}\n"
    "**Group ID**: {id}\n"
    "**Members**: {members}\n"
    "**Open to Join**: {open}\n"
    "**Recent Shout**: {shout}\n"
    "**Description**: {description}\n"
    "**Link**: https://www.roblox.com/groups/{id}\n"
    "Manually join and claim!"
)
KEYWORD_SYNONYMS = {
    "abandoned": ["unused", "empty", "forgotten"],
    "free": ["open", "available"],
    "old": ["vintage", "classic"],
    "clan": ["tribe", "guild"],
    "group": ["community", "team"]
}

cache = cachetools.TTLCache(maxsize=1000, ttl=3600)
keyword_cache = cachetools.TTLCache(maxsize=100, ttl=3600)
status_log = []
valid_proxies = []
proxy_stats = {}
webhook_queue = deque()
api_calls_made = 0
api_calls_limit = 100
api_reset_time = time.time() + 60
history_log = []
notification_sent = {}
background_task_running = False
analytics_data = {"groups_found": 0, "last_hour": []}

# Load history
try:
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            history_log = json.load(f)
except:
    history_log = []

def save_config():
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        status_log.append(f"Config save failed: {e}")

def save_history():
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history_log, f, indent=2)
    except Exception as e:
        status_log.append(f"History save failed: {e}")

def admin_required(role="view"):
    def decorator(f):
        def wrap(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('admin_login'))
            if role == "full" and session.get('role') != "full":
                status_log.append("Unauthorized access attempt")
                return "Access denied", 403
            return f(*args, **kwargs)
        wrap.__name__ = f.__name__
        return wrap
    return decorator

async def fetch_proxies(session):
    global proxy_stats
    try:
        async with session.get(PROXY_LIST_URL, timeout=10, headers={"Accept-Encoding": "gzip"}) as response:
            if response.status == 200:
                proxies = (await response.text()).splitlines()
                proxies = [p.strip() for p in proxies if p.strip()]
                valid = []
                tasks = [check_proxy(session, proxy) for proxy in proxies[:15]]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for proxy, result in zip(proxies[:15], results):
                    if result is True:
                        valid.append(proxy)
                        proxy_stats[proxy] = proxy_stats.get(proxy, {"success": 0, "fail": 0})
                status_log.append(f"Fetched {len(proxies)} proxies, {len(valid)} valid")
                return valid
            else:
                status_log.append(f"Proxy fetch failed: {response.status}")
                return []
    except Exception as e:
        status_log.append(f"Proxy fetch error: {e}")
        return []

async def check_proxy(session, proxy):
    try:
        async with session.get("https://www.google.com", proxy=proxy, timeout=5) as response:
            return response.status == 200
    except:
        return False

def send_email(subject, body):
    if not config["email"]["enabled"] or not config["notification_channels"]["email"]:
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = config["email"]["sender_email"]
        msg["To"] = config["email"]["receiver_email"]
        with smtplib.SMTP(config["email"]["smtp_server"], config["email"]["smtp_port"]) as server:
            server.starttls()
            server.login(config["email"]["sender_email"], config["email"]["sender_password"])
            server.send_message(msg)
        status_log.append(f"Email sent for {subject}")
    except Exception as e:
        status_log.append(f"Email failed: {e}")

async def send_telegram(session, message):
    if not config["telegram"]["enabled"] or not config["notification_channels"]["telegram"]:
        return
    try:
        async with session.post(
            f"https://api.telegram.org/bot{config['telegram']['bot_token']}/sendMessage",
            json={"chat_id": config["telegram"]["chat_id"], "text": message, "parse_mode": "Markdown"}
        ) as response:
            if response.status == 200:
                status_log.append("Telegram notification sent")
            else:
                status_log.append(f"Telegram failed: {response.status}")
    except Exception as e:
        status_log.append(f"Telegram error: {e}")

async def send_slack(session, message):
    if not config["slack_url"] or not config["notification_channels"]["slack"]:
        return
    try:
        async with session.post(config["slack_url"], json={"text": message}) as response:
            if response.status == 200:
                status_log.append("Slack notification sent")
            else:
                status_log.append(f"Slack failed: {response.status}")
    except Exception as e:
        status_log.append(f"Slack error: {e}")

async def send_webhook(session, group_data, template, priority=False, min_score=0):
    if group_data['score'] < min_score:
        return
    group_id = group_data['id']
    if group_id in notification_sent and time.time() - notification_sent[group_id] < config["dedup_window"]:
        return
    payload = {
        "content": template.format(
            keyword=group_data['keyword'], score=group_data['score'], name=group_data['name'],
            id=group_id, members=group_data['members'], open="Yes" if group_data['open'] else "No",
            shout=group_data['shout'], description=group_data['description'][:100] + '...'
        )
    }
    proxies = sorted(valid_proxies, key=lambda p: proxy_stats.get(p, {"success": 0, "fail": 0})["success"], reverse=True)
    if priority:
        proxies = proxies[:1]
    for attempt in range(3):
        for proxy in proxies[:3]:
            try:
                async with session.post(config["webhook_url"], json=payload, proxy=proxy, timeout=5) as response:
                    if response.status == 204:
                        proxy_stats[proxy]["success"] += 1
                        status_log.append(f"Webhook sent for group {group_id} via proxy {proxy}")
                        send_email(f"Roblox Group Found: {group_data['name']}", payload["content"])
                        await send_telegram(session, payload["content"])
                        await send_slack(session, payload["content"])
                        notification_sent[group_id] = time.time()
                        return
            except Exception as e:
                proxy_stats[proxy]["fail"] += 1
                status_log.append(f"Proxy {proxy} failed: {e}")
        await asyncio.sleep(2 ** attempt)
    try:
        async with session.post(config["webhook_url"], json=payload, timeout=5) as response:
            if response.status == 204:
                status_log.append(f"Webhook sent for group {group_id} (direct)")
                send_email(f"Roblox Group Found: {group_data['name']}", payload["content"])
                await send_telegram(session, payload["content"])
                await send_slack(session, payload["content"])
                notification_sent[group_id] = time.time()
    except Exception as e:
        status_log.append(f"Direct webhook failed: {e}")

async def send_batch_webhook(session, groups, template, min_score=0):
    groups = [g for g in groups if g['score'] >= min_score and (g['id'] not in notification_sent or time.time() - notification_sent[g['id']] >= config["dedup_window"])]
    if not groups:
        return
    content = "**Batch Group Notification**\n" + "\n".join(
        template.format(
            keyword=g['keyword'], score=g['score'], name=g['name'],
            id=g['id'], members=g['members'], open="Yes" if g['open'] else "No",
            shout=g['shout'], description=g['description'][:50] + '...'
        ) for g in groups
    )
    payload = {"content": content[:2000]}
    proxies = sorted(valid_proxies, key=lambda p: proxy_stats.get(p, {"success": 0, "fail": 0})["success"], reverse=True)
    for attempt in range(3):
        for proxy in proxies[:3]:
            try:
                async with session.post(config["webhook_url"], json=payload, proxy=proxy, timeout=5) as response:
                    if response.status == 204:
                        proxy_stats[proxy]["success"] += 1
                        status_log.append(f"Batch webhook sent for {len(groups)} groups")
                        for g in groups:
                            send_email(f"Roblox Group Found: {g['name']}", payload["content"])
                            await send_telegram(session, payload["content"])
                            await send_slack(session, payload["content"])
                            notification_sent[g['id']] = time.time()
                        return
            except Exception as e:
                proxy_stats[proxy]["fail"] += 1
                status_log.append(f"Batch proxy {proxy} failed: {e}")
        await asyncio.sleep(2 ** attempt)
    try:
        async with session.post(config["webhook_url"], json=payload, timeout=5) as response:
            if response.status == 200:
                status_log.append(f"Batch webhook sent for {len(groups)} groups (direct)")
                for g in groups:
                    notification_sent[g['id']] = time.time()
    except Exception as e:
        status_log.append(f"Direct batch webhook failed: {e}")

async def process_webhook_queue():
    async with aiohttp.ClientSession() as session:
        webhooks_sent = 0
        minute_start = time.time()
        batch = []
        while True:
            if time.time() - minute_start > 60:
                webhooks_sent = 0
                minute_start = time.time()
            if webhooks_sent >= config["webhook_rate"]:
                await asyncio.sleep(60 - (time.time() - minute_start) + 1)
                webhooks_sent = 0
                minute_start = time.time()
            if webhook_queue:
                group_data, template, priority, min_score = webhook_queue.popleft()
                if priority and group_data['score'] > 2.0:
                    await send_webhook(session, group_data, template, priority=True, min_score=min_score)
                    webhooks_sent += 1
                else:
                    batch.append(group_data)
                    if len(batch) >= 3:
                        await send_batch_webhook(session, batch, template, min_score)
                        webhooks_sent += 1
                        batch = []
            if batch:
                await send_batch_webhook(session, batch, template, min_score)
                webhooks_sent += 1
                batch = []
            await asyncio.sleep(0.1)

async def check_groups(session, group_ids, keyword, regex_pattern, activity_days, score_weights):
    global api_calls_made, api_calls_limit, api_reset_time, analytics_data
    if not group_ids:
        return []
    
    if time.time() > api_reset_time:
        api_calls_made = 0
        api_reset_time = time.time() + 60
    
    results = []
    batch_size = 20
    for i in range(0, len(group_ids), batch_size):
        batch = group_ids[i:i + batch_size]
        if api_calls_made + 1 > api_calls_limit:
            wait_time = api_reset_time - time.time() + 1
            status_log.append(f"Rate limit hit, waiting {wait_time:.1f}s")
            await asyncio.sleep(wait_time)
            api_calls_made = 0
            api_reset_time = time.time() + 60
        
        try:
            async with session.post("https://groups.roblox.com/v1/groups", json={"groupIds": batch}, headers={"Accept-Encoding": "gzip"}) as response:
                api_calls_made += 1
                headers = response.headers
                if "x-ratelimit-remaining" in headers:
                    api_calls_limit = int(headers["x-ratelimit-remaining"]) + api_calls_made
                    api_reset_time = time.time() + int(headers.get("x-ratelimit-reset", 60))
                if response.status == 200:
                    data = await response.json()
                    for group in data.get('data', []):
                        group_id = group['id']
                        if group_id in cache:
                            results.append(cache[group_id])
                            continue
                        is_ownerless = group.get('owner') is None
                        member_count = group.get('memberCount', 0)
                        is_open = group.get('publicEntryAllowed', False)
                        name = group.get('name', 'Unknown')
                        description = group.get('description', 'No description')
                        shout = group.get('shout', {}).get('body', None) if group.get('shout') else None
                        shout_time = group.get('shout', {}).get('created', None) if group.get('shout') else None
                        is_active = False
                        if shout_time:
                            shout_timestamp = time.mktime(time.strptime(shout_time, "%Y-%m-%dT%H:%M:%S.%fZ"))
                            is_active = (time.time() - shout_timestamp) < (activity_days * 86400)
                        is_unique = bool(re.match(regex_pattern, name))
                        score = (member_count * score_weights["members"]) + (score_weights["name_length"] / max(1, len(name)))
                        
                        result = {
                            'id': group_id,
                            'name': name,
                            'ownerless': is_ownerless,
                            'members': member_count,
                            'open': is_open,
                            'unique': is_unique,
                            'active': is_active,
                            'description': description[:100] + '...',
                            'shout': shout or 'None',
                            'link': f"https://www.roblox.com/groups/{group_id}",
                            'keyword': keyword,
                            'score': score,
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        cache[group_id] = result
                        if result['ownerless']:
                            analytics_data["groups_found"] += 1
                            analytics_data["last_hour"].append(time.time())
                        history_log.append(result)
                        results.append(result)
                else:
                    status_log.append(f"Batch group check failed: {response.status}")
        except Exception as e:
            status_log.append(f"Batch group check error: {e}")
        await asyncio.sleep(0.2)
    save_history()
    return results

async def scan_group_ids(session, start_id, end_id, regex_pattern, activity_days, score_weights):
    chunk_size = 100
    tasks = []
    for i in range(start_id, end_id + 1, chunk_size):
        chunk_ids = list(range(i, min(i + chunk_size, end_id + 1)))
        tasks.append(check_groups(session, chunk_ids, "ID Scan", regex_pattern, activity_days, score_weights))
    return [item for sublist in await asyncio.gather(*tasks) for item in sublist]

async def search_groups(keywords, min_members, regex_pattern, max_results, activity_days, score_weights, group_id_range, min_score):
    global api_calls_made, api_calls_limit, api_reset_time
    results = []
    expanded_keywords = []
    for kw in keywords:
        expanded_keywords.append(kw)
        expanded_keywords.extend(KEYWORD_SYNONYMS.get(kw.lower(), []))
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100)) as session:
        tasks = []
        for keyword in expanded_keywords:
            cache_key = f"{keyword}_{min_members}_{max_results}"
            if cache_key in keyword_cache:
                results.extend(keyword_cache[cache_key])
                continue
            if api_calls_made + 1 > api_calls_limit:
                wait_time = api_reset_time - time.time() + 1
                status_log.append(f"Rate limit hit, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
                api_calls_made = 0
                api_reset_time = time.time() + 60
            tasks.append(session.get(f"https://groups.roblox.com/v1/groups/search?keyword={keyword}&limit={max_results}", headers={"Accept-Encoding": "gzip"}))
            api_calls_made += 1
        
        if group_id_range:
            tasks.append(scan_group_ids(session, group_id_range[0], group_id_range[1], regex_pattern, activity_days, score_weights))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for keyword, response in zip(expanded_keywords, responses[:len(expanded_keywords)]):
            try:
                if isinstance(response, Exception):
                    status_log.append(f"Search error for keyword {keyword}: {response}")
                    continue
                if response.status == 200:
                    groups = (await response.json()).get('data', [])
                    group_ids = [g['id'] for g in groups if g.get('memberCount', 0) >= min_members]
                    group_results = await check_groups(session, group_ids, keyword, regex_pattern, activity_days, score_weights)
                    results.extend(group_results)
                    keyword_cache[cache_key] = group_results
            except Exception as e:
                status_log.append(f"Search error for keyword {keyword}: {e}")
        
        if group_id_range and isinstance(responses[-1], list):
            results.extend(responses[-1])
        
        for result in results:
            if result and result['ownerless'] and result['open'] and result['members'] >= min_members and result['unique'] and result['active']:
                webhook_queue.append((result, DEFAULT_WEBHOOK_TEMPLATE, result['score'] > 2.0, min_score))
        
    return sorted(results, key=lambda x: x.get('score', 0), reverse=True)

async def export_history_periodically():
    while config["export_schedule"]:
        await asyncio.sleep(config["export_schedule"]["interval"])
        output = io.StringIO()
        
        if config["export_schedule"]["format"] == "csv":
            writer = csv.DictWriter(output, fieldnames=['keyword', 'id', 'name', 'members', 'ownerless', 'open', 'unique', 'active', 'score', 'shout', 'description', 'link', 'timestamp'])
            writer.writeheader()
            for result in history_log:
                writer.writerow(result)
            filename = "history.csv"
            content_type = "text/csv"
        else:  # Markdown format
            output.write("# Scheduled History Export\n\n")
            output.write(f"*Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*\n\n")
            output.write("| Keyword | Name | Members | Ownerless | Open | Score | Timestamp |\n")
            output.write("|---------|------|---------|-----------|------|-------|-----------|\n")
            for result in history_log[-50:]:  # Last 50 entries
                output.write(f"| {result['keyword']} | {result['name']} | {result['members']} | {'Yes' if result['ownerless'] else 'No'} | {'Yes' if result['open'] else 'No'} | {result['score']:.1f} | {result['timestamp']} |\n")
            filename = "history.md"
            content_type = "text/markdown"
        
        output.seek(0)
        content = output.getvalue()
        
        # Send via configured channel
        if config["export_schedule"]["destination"] == "email" and config["email"]["enabled"]:
            send_email(f"Scheduled History Export - {filename}", content)
        elif config["export_schedule"]["destination"] == "telegram" and config["telegram"]["enabled"]:
            async with aiohttp.ClientSession() as session:
                await send_telegram(session, content[:2000])
        elif config["export_schedule"]["destination"] == "slack" and config["slack_url"]:
            async with aiohttp.ClientSession() as session:
                await send_slack(session, content[:2000])
        
        status_log.append(f"Scheduled export sent as {filename}")

async def refresh_proxies_periodically():
    async with aiohttp.ClientSession() as session:
        while True:
            global valid_proxies
            valid_proxies = await fetch_proxies(session)
            await asyncio.sleep(1800)

def background_tasks():
    global background_task_running
    if os.environ.get('VERCEL'):
        status_log.append("Background tasks disabled on Vercel")
        return
        
    background_task_running = True
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tasks = [
        refresh_proxies_periodically(),
        process_webhook_queue(),
        export_history_periodically(),
        search_groups(DEFAULT_SEARCH_KEYWORDS, DEFAULT_MIN_MEMBERS, DEFAULT_REGEX_PATTERN, DEFAULT_MAX_RESULTS, DEFAULT_ACTIVITY_DAYS, DEFAULT_SCORE_WEIGHTS, DEFAULT_GROUP_ID_RANGE, 0)
    ]
    loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
    while background_task_running:
        loop.run_until_complete(search_groups(DEFAULT_SEARCH_KEYWORDS, DEFAULT_MIN_MEMBERS, DEFAULT_REGEX_PATTERN, DEFAULT_MAX_RESULTS, DEFAULT_ACTIVITY_DAYS, DEFAULT_SCORE_WEIGHTS, DEFAULT_GROUP_ID_RANGE, 0))
        time.sleep(config["check_interval"])

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        for user in config["admin_users"]:
            if username == user["username"] and hashlib.sha256(password.encode()).hexdigest() == user["password"]:
                session['logged_in'] = True
                session['role'] = user["role"]
                session['username'] = username
                return redirect(url_for('admin'))
        status_log.append("Admin login failed")
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            form { max-width: 300px; }
            input { margin-bottom: 10px; width: 100%; }
            button { padding: 10px; }
        </style>
    </head>
    <body>
        <h1>Admin Login</h1>
        <form method="POST">
            <label>Username: <input type="text" name="username"></label><br>
            <label>Password: <input type="password" name="password"></label><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    ''')

@app.route('/admin', methods=['GET', 'POST'])
@admin_required(role="full")
def admin():
    global background_task_running, config
    if request.method == 'POST':
        action = request.form.get('action')
        if action == "update_config":
            config["check_interval"] = int(request.form.get('check_interval', config["check_interval"]))
            config["webhook_rate"] = int(request.form.get('webhook_rate', config["webhook_rate"]))
            config["dedup_window"] = int(request.form.get('dedup_window', config["dedup_window"]))
            export_interval = request.form.get('export_interval')
            config["notification_channels"] = {
                "discord": request.form.get('channel_discord') == "on",
                "telegram": request.form.get('channel_telegram') == "on",
                "slack": request.form.get('channel_slack') == "on",
                "email": request.form.get('channel_email') == "on"
            }
            if export_interval:
                config["export_schedule"] = {
                    "interval": int(export_interval),
                    "format": request.form.get('export_format', 'csv'),
                    "destination": request.form.get('export_destination', 'email')
                }
            else:
                config["export_schedule"] = None
            save_config()
            status_log.append("Configuration updated")
        elif action == "add_user":
            new_user = {
                "username": request.form.get('new_username'),
                "password": hashlib.sha256(request.form.get('new_password').encode()).hexdigest(),
                "role": request.form.get('new_role', 'view')
            }
            config["admin_users"].append(new_user)
            save_config()
            status_log.append(f"User {new_user['username']} added")
        elif action == "stop_task":
            background_task_running = False
            status_log.append("Background task stopped")
        elif action == "start_task":
            if not background_task_running and not os.environ.get('VERCEL'):
                threading.Thread(target=background_tasks, daemon=True).start()
                status_log.append("Background task started")
            elif os.environ.get('VERCEL'):
                status_log.append("Background tasks not supported on Vercel")
        elif action == "restart_task":
            background_task_running = False
            time.sleep(1)
            if not os.environ.get('VERCEL'):
                threading.Thread(target=background_tasks, daemon=True).start()
                status_log.append("Background task restarted")
            else:
                status_log.append("Background tasks not supported on Vercel")
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            form { margin-bottom: 20px; }
            .log { font-size: 0.9em; color: #555; }
            button { padding: 10px; margin-right: 10px; }
            .warning { color: orange; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>Admin Panel</h1>
        <p><a href="{{ url_for('home') }}">Back to Main</a> | <a href="{{ url_for('analytics') }}">Analytics</a></p>
        {% if os.environ.get('VERCEL') %}
        <p class="warning">⚠️ Running on Vercel: Background tasks are disabled</p>
        {% endif %}
        <h2>Configuration</h2>
        <form method="POST">
            <input type="hidden" name="action" value="update_config">
            <label>Check Interval (s): <input type="number" name="check_interval" value="{{ config['check_interval'] }}"></label><br>
            <label>Webhook Rate (per min): <input type="number" name="webhook_rate" value="{{ config['webhook_rate'] }}"></label><br>
            <label>Deduplication Window (s): <input type="number" name="dedup_window" value="{{ config['dedup_window'] }}"></label><br>
            <label>Export Interval (s): <input type="number" name="export_interval" value="{{ config['export_schedule']['interval'] if config['export_schedule'] else '' }}"></label><br>
            <label>Export Format: <select name="export_format">
                <option value="csv" {% if config['export_schedule'] and config['export_schedule']['format'] == 'csv' %}selected{% endif %}>CSV</option>
                <option value="md" {% if config['export_schedule'] and config['export_schedule']['format'] == 'md' %}selected{% endif %}>Markdown</option>
            </select></label><br>
            <label>Export Destination: <select name="export_destination">
                <option value="email" {% if config['export_schedule'] and config['export_schedule']['destination'] == 'email' %}selected{% endif %}>Email</option>
                <option value="telegram" {% if config['export_schedule'] and config['export_schedule']['destination'] == 'telegram' %}selected{% endif %}>Telegram</option>
                <option value="slack" {% if config['export_schedule'] and config['export_schedule']['destination'] == 'slack' %}selected{% endif %}>Slack</option>
            </select></label><br>
            <label><input type="checkbox" name="channel_discord" {% if config['notification_channels']['discord'] %}checked{% endif %}> Discord</label><br>
            <label><input type="checkbox" name="channel_telegram" {% if config['notification_channels']['telegram'] %}checked{% endif %}> Telegram</label><br>
            <label><input type="checkbox" name="channel_slack" {% if config['notification_channels']['slack'] %}checked{% endif %}> Slack</label><br>
            <label><input type="checkbox" name="channel_email" {% if config['notification_channels']['email'] %}checked{% endif %}> Email</label><br>
            <button type="submit">Update Config</button>
        </form>
        <h2>Add User</h2>
        <form method="POST">
            <input type="hidden" name="action" value="add_user">
            <label>Username: <input type="text" name="new_username"></label><br>
            <label>Password: <input type="password" name="new_password"></label><br>
            <label>Role: <select name="new_role">
                <option value="view">View Only</option>
                <option value="full">Full Access</option>
            </select></label><br>
            <button type="submit">Add User</button>
        </form>
        <h2>Task Control</h2>
        <form method="POST">
            <input type="hidden" name="action" value="start_task">
            <button type="submit" {% if os.environ.get('VERCEL') %}disabled title="Not supported on Vercel"{% endif %}>Start Background Task</button>
        </form>
        <form method="POST">
            <input type="hidden" name="action" value="stop_task">
            <button type="submit">Stop Background Task</button>
        </form>
        <form method="POST">
            <input type="hidden" name="action" value="restart_task">
            <button type="submit" {% if os.environ.get('VERCEL') %}disabled title="Not supported on Vercel"{% endif %}>Restart Background Task</button>
        </form>
        <h2>Status Log</h2>
        <div class="log">
            {% for log in status_log %}
            <p>{{ log }}</p>
            {% endfor %}
        </div>
        <form action="/export_logs" method="POST">
            <button type="submit">Export Full Log (CSV)</button>
        </form>
        <form action="/export_logs_md" method="POST">
            <button type="submit">Export Full Log (Markdown)</button>
        </form>
    </body>
    </html>
    ''', config=config, status_log=status_log)

@app.route('/analytics', methods=['GET'])
@admin_required(role="view")
def analytics():
    global analytics_data
    last_hour_count = len([t for t in analytics_data["last_hour"] if time.time() - t < 3600])
    analytics_data["last_hour"] = [t for t in analytics_data["last_hour"] if time.time() - t < 3600]
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Analytics Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .chart { width: 100%; height: 20px; background-color: #f3f3f3; border-radius: 5px; }
            .chart-fill { height: 20px; background-color: #4caf50; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>Analytics Dashboard</h1>
        <p><a href="{{ url_for('admin') }}">Back to Admin</a></p>
        <p>Total Groups Found: {{ analytics_data['groups_found'] }}</p>
        <p>Groups Found Last Hour: {{ last_hour_count }}</p>
        <div class="chart">
            <div class="chart-fill" style="width: {{ (last_hour_count / 10 * 100) | round(1) }}%;"></div>
        </div>
    </body>
    </html>
    ''', analytics_data=analytics_data, last_hour_count=last_hour_count)

@app.route('/api/groups', methods=['GET'])
@admin_required(role="view")
def api_groups():
    return jsonify(history_log[-50:])

@app.route('/', methods=['GET', 'POST'])
def home():
    keywords = DEFAULT_SEARCH_KEYWORDS
    min_members = DEFAULT_MIN_MEMBERS
    regex_pattern = DEFAULT_REGEX_PATTERN
    max_results = DEFAULT_MAX_RESULTS
    activity_days = DEFAULT_ACTIVITY_DAYS
    webhook_template = DEFAULT_WEBHOOK_TEMPLATE
    score_weights = DEFAULT_SCORE_WEIGHTS
    group_id_range = DEFAULT_GROUP_ID_RANGE
    min_score = 0
    results = []
    
    if request.method == 'POST':
        keywords = request.form.get('keywords', ','.join(DEFAULT_SEARCH_KEYWORDS)).split(',')
        min_members = int(request.form.get('min_members', DEFAULT_MIN_MEMBERS))
        regex_pattern = request.form.get('regex_pattern', DEFAULT_REGEX_PATTERN)
        max_results = int(request.form.get('max_results', DEFAULT_MAX_RESULTS))
        activity_days = int(request.form.get('activity_days', DEFAULT_ACTIVITY_DAYS))
        webhook_template = request.form.get('webhook_template', webhook_template)
        score_weights = {
            "members": float(request.form.get('score_members', DEFAULT_SCORE_WEIGHTS["members"])),
            "name_length": float(request.form.get('score_name_length', DEFAULT_SCORE_WEIGHTS["name_length"]))
        }
        group_id_range = (
            int(request.form.get('group_id_start', DEFAULT_GROUP_ID_RANGE[0])),
            int(request.form.get('group_id_end', DEFAULT_GROUP_ID_RANGE[1]))
        )
        min_score = float(request.form.get('min_score', 0))
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(search_groups(keywords, min_members, regex_pattern, max_results, activity_days, score_weights, group_id_range, min_score))
    
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Roblox Group Finder</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            form { margin-bottom: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            .notify { color: green; font-weight: bold; }
            button { padding: 10px; margin-top: 10px; }
            .log { font-size: 0.9em; color: #555; }
            textarea { width: 100%; height: 100px; }
            .progress-bar { width: 100%; background-color: #f3f3f3; border-radius: 5px; }
            .progress-fill { height: 20px; background-color: #4caf50; border-radius: 5px; }
            .warning { color: orange; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>Roblox Ownerless Group Finder</h1>
        {% if os.environ.get('VERCEL') %}
        <p class="warning">⚠️ Running on Vercel: Background scanning disabled. Use manual search.</p>
        {% endif %}
        <p>Search for ownerless groups with ultra-fast scanning, customizable notifications (Discord/Telegram/Slack/email), and Proxifly proxies (no signup). Manually claim via links.</p>
        <p><a href="{{ url_for('admin_login') }}">Admin Panel</a></p>
        <p><strong>API Usage:</strong> {{ api_calls_made }}/{{ api_calls_limit }} calls (resets in {{ (api_reset_time - time.time()) | round(1) }}s)</p>
        <div class="progress-bar">
            <div class="progress-fill" style="width: {{ (api_calls_made / api_calls_limit * 100) | round(1) }}%;"></div>
        </div>
        
        <form method="POST">
            <label>Search Keywords (comma-separated): <input type="text" name="keywords" value="{{ ','.join(keywords) }}"></label><br>
            <label>Min Members: <input type="number" name="min_members" value="{{ min_members }}"></label><br>
            <label>Unique Name Regex: <input type="text" name="regex_pattern" value="{{ regex_pattern }}"></label><br>
            <label>Max Results per Keyword: <input type="number" name="max_results" value="{{ max_results }}"></label><br>
            <label>Max Shout Age (days): <input type="number" name="activity_days" value="{{ activity_days }}"></label><br>
            <label>Group ID Range: <input type="number" name="group_id_start" value="{{ group_id_range[0] }}"> to <input type="number" name="group_id_end" value="{{ group_id_range[1] }}"></label><br>
            <label>Score Weights - Members: <input type="number" step="0.001" name="score_members" value="{{ score_weights['members'] }}"></label><br>
            <label>Score Weights - Name Length: <input type="number" step="0.1" name="score_name_length" value="{{ score_weights['name_length'] }}"></label><br>
            <label>Min Notification Score: <input type="number" step="0.1" name="min_score" value="{{ min_score }}"></label><br>
            <label>Webhook Template: <textarea name="webhook_template">{{ webhook_template }}</textarea></label><br>
            <button type="submit">Search</button>
        </form>
        <form action="/export_csv" method="POST">
            <input type="hidden" name="results" value="{{ results | tojson }}">
            <button type="submit">Export Results to CSV</button>
        </form>
        <form action="/export_md" method="POST">
            <input type="hidden" name="results" value="{{ results | tojson }}">
            <button type="submit">Export Results to Markdown</button>
        </form>
        <form action="/export_history" method="POST">
            <button type="submit">Export Search History (CSV)</button>
        </form>
        <form action="/export_history_md" method="POST">
            <button type="submit">Export Search History (Markdown)</button>
        </form>
        
        {% if results %}
        <h2>Results for "{{ keywords | join(', ') }}"</h2>
        <table>
            <tr>
                <th>Keyword</th>
                <th>Name</th>
                <th>Members</th>
                <th>Ownerless</th>
                <th>Open</th>
                <th>Unique</th>
                <th>Active</th>
                <th>Score</th>
                <th>Shout</th>
                <th>Description</th>
                <th>Link</th>
                <th>Notification Sent</th>
            </tr>
            {% for result in results %}
            <tr>
                <td>{{ result.keyword }}</td>
                <td>{{ result.name }}</td>
                <td>{{ result.members }}</td>
                <td>{{ 'Yes' if result.ownerless else 'No' }}</td>
                <td>{{ 'Yes' if result.open else 'No' }}</td>
                <td>{{ 'Yes' if result.unique else 'No' }}</td>
                <td>{{ 'Yes' if result.active else 'No' }}</td>
                <td>{{ result.score | round(1) }}</td>
                <td>{{ result.shout }}</td>
                <td>{{ result.description }}</td>
                <td><a href="{{ result.link }}" target="_blank">View Group</a></td>
                <td>{% if result.ownerless and result.open and result.members >= min_members and result.unique and result.active %}<span class="notify">Yes</span>{% else %}No{% endif %}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        <h3>Status Log</h3>
        <div class="log">
            {% for log in status_log[-10:] %}
            <p>{{ log }}</p>
            {% endfor %}
        </div>
    </body>
    </html>
    ''', keywords=keywords, min_members=min_members, regex_pattern=regex_pattern, max_results=max_results, activity_days=activity_days, webhook_template=webhook_template, score_weights=score_weights, group_id_range=group_id_range, min_score=min_score, results=results, status_log=status_log, api_calls_made=api_calls_made, api_calls_limit=api_calls_limit, api_reset_time=api_reset_time)

@app.route('/export_csv', methods=['POST'])
def export_csv():
    results = request.form.get('results')
    if not results:
        return "No results to export", 400
    
    results = json.loads(results)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['keyword', 'id', 'name', 'members', 'ownerless', 'open', 'unique', 'active', 'score', 'shout', 'description', 'link', 'timestamp'])
    writer.writeheader()
    for result in results:
        writer.writerow(result)
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='group_results.csv'
    )

@app.route('/export_md', methods=['POST'])
def export_md():
    results = request.form.get('results')
    if not results:
        return "No results to export", 400
    
    results = json.loads(results)
    output = io.StringIO()
    
    # Create markdown content
    output.write("# Roblox Group Finder Results\n\n")
    output.write(f"*Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*\n\n")
    
    if results:
        output.write("## Summary\n")
        output.write(f"- **Total Groups Found**: {len(results)}\n")
        output.write(f"- **Ownerless Groups**: {len([r for r in results if r['ownerless']])}\n")
        output.write(f"- **Open Groups**: {len([r for r in results if r['open']])}\n")
        output.write(f"- **Active Groups**: {len([r for r in results if r['active']])}\n\n")
        
        output.write("## Group Details\n\n")
        output.write("| Keyword | Name | Members | Ownerless | Open | Unique | Active | Score | Link |\n")
        output.write("|---------|------|---------|-----------|------|--------|--------|-------|------|\n")
        
        for result in results:
            output.write(f"| {result['keyword']} | {result['name']} | {result['members']} | {'✅' if result['ownerless'] else '❌'} | {'✅' if result['open'] else '❌'} | {'✅' if result['unique'] else '❌'} | {'✅' if result['active'] else '❌'} | {result['score']:.1f} | [View]({result['link']}) |\n")
        
        output.write("\n## Detailed Information\n\n")
        for i, result in enumerate(results, 1):
            output.write(f"### {i}. {result['name']} (ID: {result['id']})\n")
            output.write(f"- **Keyword**: {result['keyword']}\n")
            output.write(f"- **Members**: {result['members']}\n")
            output.write(f"- **Ownerless**: {'Yes' if result['ownerless'] else 'No'}\n")
            output.write(f"- **Open to Join**: {'Yes' if result['open'] else 'No'}\n")
            output.write(f"- **Unique Name**: {'Yes' if result['unique'] else 'No'}\n")
            output.write(f"- **Active**: {'Yes' if result['active'] else 'No'}\n")
            output.write(f"- **Score**: {result['score']:.1f}\n")
            output.write(f"- **Shout**: {result['shout']}\n")
            output.write(f"- **Description**: {result['description']}\n")
            output.write(f"- **Link**: {result['link']}\n")
            output.write(f"- **Timestamp**: {result['timestamp']}\n\n")
    else:
        output.write("No groups found matching your criteria.\n")
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/markdown',
        as_attachment=True,
        download_name=f'roblox_groups_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.md'
    )

@app.route('/export_history', methods=['POST'])
def export_history():
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['keyword', 'id', 'name', 'members', 'ownerless', 'open', 'unique', 'active', 'score', 'shout', 'description', 'link', 'timestamp'])
    writer.writeheader()
    for result in history_log:
        writer.writerow(result)
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='history.csv'
    )

@app.route('/export_history_md', methods=['POST'])
def export_history_md():
    output = io.StringIO()
    
    # Create markdown content
    output.write("# Roblox Group Finder - Search History\n\n")
    output.write(f"*Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*\n\n")
    output.write(f"*Total searches in history: {len(history_log)}*\n\n")
    
    if history_log:
        # Summary statistics
        ownerless_count = len([r for r in history_log if r['ownerless']])
        open_count = len([r for r in history_log if r['open']])
        active_count = len([r for r in history_log if r['active']])
        
        output.write("## Summary Statistics\n")
        output.write(f"- **Total Searches**: {len(history_log)}\n")
        output.write(f"- **Ownerless Groups Found**: {ownerless_count}\n")
        output.write(f"- **Open Groups Found**: {open_count}\n")
        output.write(f"- **Active Groups Found**: {active_count}\n")
        output.write(f"- **Success Rate**: {(ownerless_count/len(history_log)*100 if history_log else 0):.1f}%\n\n")
        
        # Group by keyword
        output.write("## Results by Keyword\n")
        keyword_stats = {}
        for result in history_log:
            keyword = result['keyword']
            if keyword not in keyword_stats:
                keyword_stats[keyword] = {'count': 0, 'ownerless': 0, 'open': 0, 'active': 0}
            keyword_stats[keyword]['count'] += 1
            if result['ownerless']:
                keyword_stats[keyword]['ownerless'] += 1
            if result['open']:
                keyword_stats[keyword]['open'] += 1
            if result['active']:
                keyword_stats[keyword]['active'] += 1
        
        output.write("| Keyword | Total | Ownerless | Open | Active | Success Rate |\n")
        output.write("|---------|-------|-----------|------|--------|-------------|\n")
        for keyword, stats in keyword_stats.items():
            success_rate = (stats['ownerless']/stats['count']*100) if stats['count'] > 0 else 0
            output.write(f"| {keyword} | {stats['count']} | {stats['ownerless']} | {stats['open']} | {stats['active']} | {success_rate:.1f}% |\n")
        
        output.write("\n## Recent Searches (Last 50)\n\n")
        output.write("| Timestamp | Keyword | Name | Members | Ownerless | Open | Score |\n")
        output.write("|-----------|---------|------|---------|-----------|------|-------|\n")
        
        recent_log = history_log[-50:]  # Last 50 entries
        for result in recent_log:
            output.write(f"| {result['timestamp']} | {result['keyword']} | {result['name']} | {result['members']} | {'✅' if result['ownerless'] else '❌'} | {'✅' if result['open'] else '❌'} | {result['score']:.1f} |\n")
        
        output.write("\n## Full Search Details\n\n")
        for i, result in enumerate(recent_log, 1):
            output.write(f"### {i}. {result['name']} (ID: {result['id']})\n")
            output.write(f"- **Timestamp**: {result['timestamp']}\n")
            output.write(f"- **Keyword**: {result['keyword']}\n")
            output.write(f"- **Members**: {result['members']}\n")
            output.write(f"- **Ownerless**: {'Yes' if result['ownerless'] else 'No'}\n")
            output.write(f"- **Open to Join**: {'Yes' if result['open'] else 'No'}\n")
            output.write(f"- **Unique Name**: {'Yes' if result['unique'] else 'No'}\n")
            output.write(f"- **Active**: {'Yes' if result['active'] else 'No'}\n")
            output.write(f"- **Score**: {result['score']:.1f}\n")
            output.write(f"- **Shout**: {result['shout']}\n")
            output.write(f"- **Description**: {result['description']}\n")
            output.write(f"- **Link**: {result['link']}\n\n")
    else:
        output.write("No search history available.\n")
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/markdown',
        as_attachment=True,
        download_name=f'search_history_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.md'
    )

@app.route('/export_logs', methods=['POST'])
@admin_required(role="view")
def export_logs():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Log"])
    for log in status_log:
        writer.writerow([datetime.utcnow().isoformat(), log])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='status_log.csv'
    )

@app.route('/export_logs_md', methods=['POST'])
@admin_required(role="view")
def export_logs_md():
    output = io.StringIO()
    
    # Create markdown content
    output.write("# Roblox Group Finder - Status Log\n\n")
    output.write(f"*Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*\n\n")
    output.write(f"*Total log entries: {len(status_log)}*\n\n")
    
    if status_log:
        # Count log types
        error_count = len([log for log in status_log if 'error' in log.lower() or 'fail' in log.lower()])
        success_count = len([log for log in status_log if 'success' in log.lower() or 'sent' in log.lower()])
        warning_count = len([log for log in status_log if 'warning' in log.lower() or 'rate limit' in log.lower()])
        
        output.write("## Log Summary\n")
        output.write(f"- **Total Entries**: {len(status_log)}\n")
        output.write(f"- **Success Messages**: {success_count}\n")
        output.write(f"- **Warning Messages**: {warning_count}\n")
        output.write(f"- **Error Messages**: {error_count}\n\n")
        
        output.write("## Recent Log Entries (Last 100)\n\n")
        output.write("| Timestamp | Message |\n")
        output.write("|-----------|---------|\n")
        
        recent_logs = status_log[-100:]  # Last 100 entries
        for log in recent_logs:
            # Add appropriate emoji based on log type
            emoji = "✅"
            if 'error' in log.lower() or 'fail' in log.lower():
                emoji = "❌"
            elif 'warning' in log.lower() or 'rate limit' in log.lower():
                emoji = "⚠️"
            elif 'start' in log.lower() or 'login' in log.lower():
                emoji = "🔒"
            elif 'proxy' in log.lower():
                emoji = "🔗"
            
            output.write(f"| {datetime.utcnow().isoformat()} | {emoji} {log} |\n")
        
        output.write("\n## Full Log Details\n\n")
        for i, log in enumerate(recent_logs, 1):
            output.write(f"{i}. **{datetime.utcnow().isoformat()}** - {log}\n")
    else:
        output.write("No log entries available.\n")
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/markdown',
        as_attachment=True,
        download_name=f'status_log_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.md'
    )

# Start background tasks only if not on Vercel
if not os.environ.get('VERCEL'):
    threading.Thread(target=background_tasks, daemon=True).start()

app = app
