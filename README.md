Snort-Watcher
this script is used for watch snort alert on database and send them by email in linux systems

mysql and barnyard must installed and configured then snort-watcher read data from database

please change variable of database information and email in script

first install mysql-connector :

pip3 install mysql-connector-python

for use it you must add script to crontab and set time for runing for example

in /etc/crontab

5 * * * * root python3 /root/Snort-Watcher.py

check database every hour
