#!/bin/bash
set -euo pipefail

echo "[1/5] Installing research tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y tcpdump tshark cmake libpcap-dev

echo "[2/5] Backing up Asterisk configs"
cp -a /etc/asterisk/logger.conf /etc/asterisk/logger.conf.pre-research
cp -a /etc/asterisk/asterisk.conf /etc/asterisk/asterisk.conf.pre-research

echo "[3/5] Enabling Azure-style full Asterisk log"
if ! grep -q '^full => ' /etc/asterisk/logger.conf; then
  sed -i '/^messages\.log => notice,warning,error/a full => notice,warning,error,debug,verbose,dtmf,fax' /etc/asterisk/logger.conf
fi

echo "[4/5] Allowing astrix user to use Asterisk CLI without sudo"
sed -i 's/^;astctlpermissions = .*/astctlpermissions = 0660/' /etc/asterisk/asterisk.conf
sed -i 's/^;astctlowner = .*/astctlowner = root/' /etc/asterisk/asterisk.conf
sed -i 's/^;astctlgroup = .*/astctlgroup = astrix/' /etc/asterisk/asterisk.conf

echo "[5/5] Enabling unprivileged packet capture and restarting Asterisk"
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
systemctl restart asterisk
sleep 2
chmod 0644 /var/log/asterisk/full 2>/dev/null || true

echo
echo "ROOT BOOTSTRAP COMPLETE"
echo "Asterisk:"
systemctl is-active asterisk
echo "Full log:"
ls -lh /var/log/asterisk/full
echo "tcpdump capabilities:"
getcap /usr/bin/tcpdump
