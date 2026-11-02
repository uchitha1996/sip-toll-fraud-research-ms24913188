#!/bin/bash
set -e
cp -a /etc/asterisk/asterisk.conf /etc/asterisk/asterisk.conf.pre-cli-fix
sed -i 's/^;\[files\]/[files]/' /etc/asterisk/asterisk.conf
systemctl restart asterisk
sleep 2
echo "CLI socket:"
stat -c '%U %G %a %n' /var/run/asterisk/asterisk.ctl
