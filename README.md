What
====

Small tool to probe and keep history of the SSL/TLS support of SMTP servers.

How
===

1. Create a file with one SMTP domain per line.
   Default name: domain_list
2. Run launch.sh
3. See the content of dump.txt

Notes
=====

The history is keept in a redis database (so you need a redis-server binary) and
all the domains in the 'domains' set will be probed each time you run the script.

