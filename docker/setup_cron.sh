#!/usr/bin/env sh

if [ ! -z "$CRON_EXPRESSION" ]; then
    CRONTAB="$CRON_EXPRESSION UNATTENDED=1 /script/immich_auto_album.sh > /proc/1/fd/1 2>/proc/1/fd/2"
    # Reset crontab
    crontab -r
    (crontab -l 2>/dev/null; echo "$CRONTAB") | crontab -

    # Make environment variables accessible to cron
    printenv > /etc/environment
fi
