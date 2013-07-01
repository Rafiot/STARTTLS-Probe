#!/bin/bash

set -e

echo -n 'Starting redis...'
bash ./launch_local_redis.sh
echo ' done.'

echo -n 'Adding domains to probe...'
cat domain_list | python populate.py
echo ' done.'

echo -n 'Launch probes...'
for i in {1..10}; do
    python probe.py --history &
done
python probe.py --history
echo ' done.'

while [ `redis-cli -s ./redis.sock client list | wc -l` -gt 1 ]; do
    sleep 1
done

echo -n 'Dumping latest date...'
python dump.py
echo ' done.'

redis-cli -s ./redis.sock shutdown

