#!/bin/bash

set -e

echo -n 'Starting redis...'
bash ./launch_local_redis.sh
sleep 3
#FIXME: make sure the db is loaded
echo ' done.'

echo -n 'Adding domains to probe...'
cat domain_list | python populate.py
echo ' done.'

echo -n 'Launch probes...'
for i in {1..10}; do
    python probe.py &
done
python probe.py
echo ' done.'

while [ `redis-cli -s ./redis.sock client list | wc -l` -gt 1 ]; do
    sleep 1
done

echo -n 'Dumping latest date...'
python dump.py
echo ' done.'

redis-cli -s ./redis.sock shutdown

