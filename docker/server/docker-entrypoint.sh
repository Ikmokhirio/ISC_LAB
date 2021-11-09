#!/bin/bash

# Remove the pid file if it exists
FILE=/var/run/suricata.pid
if test -f "$FILE"; then
    rm "$FILE"
fi

# Kill suricata by name to eliminate child processes and prevent old configurations from ran$
pkill -f "suricata"

suricata -D --pidfile /var/run/suricata.pid -c /usr/src/suricata/suricata.yaml -s /usr/src/suricata/rules/my_custom.rules -i eth0 && python3 /usr/src/server/server.py

