#!/bin/bash
# /opt/ti-mirror/healthcheck.sh
# Quick health check for TI Mirror server

echo "═══════════════════════════════════════════════"
echo "  TI Mirror Health Check — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "═══════════════════════════════════════════════"
echo ""

# ─── Services ─────────────────────────────────
echo "▶ SERVICES"
echo "  Nginx:      $(systemctl is-active nginx)"
echo "  Cron:       $(systemctl is-active cron)"
echo "  Logrotate:  $(systemctl is-active logrotate.timer)"
echo ""

# ─── Cron ─────────────────────────────────────
echo "▶ CRON (root)"
sudo crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$"
echo ""

# ─── Feeds ────────────────────────────────────
echo "▶ FEEDS STATUS"
if [ -f /var/www/html/feeds/_metadata.json ]; then
    python3 -c "
import json
with open('/var/www/html/feeds/_metadata.json') as f:
    m = json.load(f)
print(f\"  Last run:      {m['last_run']}\")
print(f\"  Total feeds:   {m['feed_count']}\")
print(f\"  OK:            {m['ok_count']}\")
print(f\"  Errors:        {m['error_count']}\")
if m['error_count'] > 0:
    print('  ⚠ Failing feeds:')
    for feed in m['feeds']:
        if feed['status'] != 'ok':
            print(f\"    - {feed['name']}: {feed.get('error', 'unknown')}\")
"
else
    echo "  ❌ metadata.json not found!"
fi
echo ""

# ─── Feed Files ───────────────────────────────
echo "▶ FEED FILES"
ls -la /var/www/html/feeds/*.{txt,csv,json,dat,zip} 2>/dev/null | awk '{print "  " $5 "  " $6 " " $7 " " $8 "  " $9}'
echo ""

# ─── Recent Errors ────────────────────────────
echo "▶ RECENT ERRORS (last 24h)"
ERR_COUNT=$(sudo find /var/log/ti-mirror.log -mtime -1 -exec grep -c "ERROR\|FAILED" {} \; 2>/dev/null || echo 0)
echo "  Error lines in last 24h: $ERR_COUNT"
if [ "$ERR_COUNT" -gt 0 ]; then
    echo "  Recent error samples:"
    sudo grep "ERROR\|FAILED" /var/log/ti-mirror.log 2>/dev/null | tail -5 | sed 's/^/    /'
fi
echo ""

# ─── Logrotate ────────────────────────────────
echo "▶ LOGROTATE"
echo "  Rotated files:"
ls -la /var/log/ti-mirror.log.*.gz 2>/dev/null | awk '{print "    " $5 "  " $9}' || echo "    (none yet)"
echo "  Last state:"
grep ti-mirror /var/lib/logrotate/status 2>/dev/null | sed 's/^/    /'
echo ""

# ─── Disk Usage ───────────────────────────────
echo "▶ DISK"
echo "  /var/www/html/feeds: $(du -sh /var/www/html/feeds 2>/dev/null | cut -f1)"
echo "  /var/log/ti-mirror*: $(du -sh /var/log/ti-mirror* 2>/dev/null | awk '{s+=$1} END {print s}' 2>/dev/null || echo '0')"
echo ""

echo "═══════════════════════════════════════════════"
echo "  Health check complete"
echo "═══════════════════════════════════════════════"
