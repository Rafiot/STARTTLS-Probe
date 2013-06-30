#!/bin/bash

set -e

bash ./launch_local_redis.sh
sleep 5
echo 'Redis started'
cat domain_list | python populate.py

echo -n 'Domains added, launch probes...'
for i in {1..10}; do
    python probe.py &
done
python probe.py
echo 'done.'

while [ `redis-cli -s ./redis.sock client list | wc -l` -gt 1 ]; do
    sleep 1
done
redis-cli -s ./redis.sock shutdown

