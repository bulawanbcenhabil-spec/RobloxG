# Roblox Ownerless Group Finder

A Flask-based web application for ultra-fast scanning of ownerless Roblox groups with Discord/Telegram/Slack/email notifications. Optimized for Vercel hosting with a secure admin panel and API endpoint. Uses public Roblox APIs and free Proxifly proxies (no signup required).

## Features

- **Ultra-Fast Search**: Parallel keyword searches, batch API requests, parallel group ID scanning, and gzip compression.
- **Admin Panel**: Secure interface for managing settings, users, tasks, and analytics (username: `admin`, password: `admin123`).
- **Advanced Filters**: Filter by minimum members, regex names, recent activity, and custom scoring.
- **Notifications**: Customizable Discord/Telegram/Slack/email notifications with priority queuing, batch sending, and deduplication.
- **Export Options**: Download results/history as CSV/Markdown; schedule exports to email/Telegram/Slack.
- **Analytics Dashboard**: View group find trends (e.g., groups found per hour).
- **API Endpoint**: Access recent groups via `/api/groups`.
- **Status Monitoring**: Real-time API usage, proxy stats, and logs.
- **Performance**: Optimized with `aiohttp` (connection pooling), `cachetools` (keyword caching), and Vercel serverless.
- **Compliance**: No automation of joining/claiming; manual claiming required.

## Prerequisites

- Python 3.8+
- A Discord server with a webhook
- Optional: Telegram bot token, Slack webhook, SMTP server (e.g., Gmail)
- Vercel account for hosting
- Internet access for Roblox APIs and proxy fetching

## Setup Instructions

### Local Setup

1. **Install Dependencies**:

   ```bash
   pip install flask aiohttp cachetools
   ```

   Installs Flask, `aiohttp`, and `cachetools`.

2. **Configure Environment**:

   - Create a `.env` file or set environment variables:

     ```bash
     SECRET_KEY=your_secret_key
     WEBHOOK_URL=https://webhook.lewisakura.moe/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN/queue
     SLACK_URL=your_slack_webhook
     TELEGRAM_ENABLED=False
     TELEGRAM_BOT_TOKEN=your_bot_token
     TELEGRAM_CHAT_ID=your_chat_id
     EMAIL_ENABLED=False
     EMAIL_SMTP_SERVER=smtp.gmail.com
     EMAIL_SMTP_PORT=587
     EMAIL_SENDER=your_email@gmail.com
     EMAIL_PASSWORD=your_app_password
     EMAIL_RECEIVER=your_email@gmail.com
     ```

3. **Run Locally**:

   ```bash
   python app.py
   ```

   - Access at `http://localhost:5000`.
   - Admin panel at `http://localhost:5000/admin` (login required).

### Vercel Deployment

1. **Prepare Files**:

   - Save `app.py`, `vercel.json`, and `requirements.txt`:

     ```bash
     echo "flask==2.0.1\naiohttp==3.8.3\ncachetools==5.2.0" > requirements.txt
     ```

   - Push to a GitHub repository.

2. **Deploy to Vercel**:

   - Log in to Vercel and import your repository.
   - Set environment variables in Vercel’s dashboard (same as `.env` above).
   - Deploy the project. Vercel will use `vercel.json` to configure the Flask app.
   - Access at your Vercel URL (e.g., `https://your-app.vercel.app`).

3. **Configure Notifications**:

   - Update `WEBHOOK_URL` (Discord), `SLACK_URL`, `TELEGRAM_*`, and `EMAIL_*` in Vercel’s environment variables.
   - Enable desired channels in the admin panel.

4. **Configure Admin Credentials**:

   - Add users via the admin panel (`/admin`) or modify `config.json` manually.

## Usage

- **Web Interface**: Visit `/` to search for groups by keywords, minimum members, regex pattern, max results, group ID range, and custom scoring. Results are sorted by score.
- **Admin Panel**: Access `/admin` to manage settings, users, tasks, and view logs/analytics. Requires login.
- **Analytics**: View group find trends at `/analytics`.
- **API**: Fetch recent groups via `/api/groups` (admin access required).
- **Notifications**: Ownerless, open-entry, active groups trigger customizable notifications with deduplication.
- **Claiming Groups**: Manually visit group links, join, and claim via Roblox’s admin page.
- **Export**: Download results/history as CSV/Markdown; schedule exports via admin panel.
- **Status**: Monitor API usage, proxy performance, and logs in real-time.

## Compliance with Roblox Terms of Service

- **No Automation**: Only searches and notifies; manual claiming required.
- **Public APIs**: Uses `groups/v1/groups/search` and `groups/v1/groups` without authentication.
- **Rate Limits**: Respects Roblox’s 60-100 requests/minute limit with adaptive throttling.
- **No Robux Checks**: Avoids private APIs to prevent TOS violations.

## Notes

- **Proxies**: Fetched from Proxifly’s HTTP proxy list (no signup, updated every 5 minutes). Refreshed every 30 minutes with health monitoring; falls back to direct sending.
- **Rate Limits**: Adjust `check_interval` or `max_results` in admin panel if blocked.
- **Performance**: Parallel ID scanning, gzip compression, and caching ensure speed.
- **Limitations**: Cannot check group Robux (requires authentication). Default regex is 3-5 alphanumeric chars.
- **Vercel**: Serverless environment may limit long-running tasks; background tasks restart automatically.

## Troubleshooting

- **ModuleNotFoundError**:
  - Run `pip install flask aiohttp cachetools`.
  - Ensure `requirements.txt` is correct for Vercel.
- **Proxy Issues**: Check status log; use TheSpeedX/PROXY-List.
- **API Errors**: Adjust scan settings in admin panel.
- **Notification Issues**: Verify webhook URLs and channel settings in admin panel.
- **Admin Access**: Ensure `admin_users` in `config.json` or environment variables are set.
- **Vercel Deployment**: Check Vercel logs for errors; ensure `vercel.json` and environment variables are correct.

## Contributing

Fork and submit pull requests for improvements, such as:

- Additional notification channels (e.g., WhatsApp).
- In-game Roblox integration.
- Enhanced analytics visualizations.

## License

MIT License. Use responsibly and respect Roblox’s Terms of Service.

## Disclaimer

For educational purposes only. Misuse may violate Roblox’s TOS and result in bans. Claim groups manually and ethically.