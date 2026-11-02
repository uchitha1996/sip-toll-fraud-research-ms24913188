#!/usr/bin/env python3
"""Prepare restricted account-1002 SIPp REGISTER and 88002 INVITE XML in the PBX lab."""
import os
import re
from pathlib import Path

CONFIG = Path("/etc/asterisk/pjsip.conf")
TEMPLATE = Path("/home/astrix/sipp-lab/failed_password_register_1002.xml")
INVITE = Path("/home/astrix/sip-fraud-research/scripts/invite_auth_1001_template.xml")
OUT = Path("/home/astrix/sip-fraud-research/datasets/emulated-outbound-runs/.valid_register_1002.xml")

def main():
    os.umask(0o077)
    blocks = re.findall(r"(?ms)^\[1002-auth\]\s*\n(.*?)(?=^\[|\Z)", CONFIG.read_text())
    if len(blocks) != 1:
        raise RuntimeError("Expected exactly one 1002 auth block")
    values = re.findall(r"(?m)^password\s*=\s*(\S+)\s*$", blocks[0])
    if len(values) != 1 or not re.fullmatch(r"[^\s\]]{1,128}", values[0]):
        raise RuntimeError("Unexpected credential format")
    register = TEMPLATE.read_text()
    if register.count("WrongLabPassword") != 1 or register.count("1002") < 5:
        raise RuntimeError("Unexpected REGISTER template")
    if register.count('<recv response="401"/>') != 1:
        raise RuntimeError("Unexpected final REGISTER response")
    register = register.replace("WrongLabPassword", values[0]).replace(
        '<recv response="401"/>', '<recv response="200"/>')
    OUT.write_text(register)
    OUT.chmod(0o600)
    invite = INVITE.read_text()
    if invite.count("LAB_PASSWORD_PLACEHOLDER") != 1 or invite.count("1001") < 5:
        raise RuntimeError("Unexpected INVITE template")
    invite = invite.replace("1001", "1002").replace("88001", "88002")
    invite = invite.replace("LAB_PASSWORD_PLACEHOLDER", values[0])
    invite_out = OUT.with_name(".valid_invite_1002.xml")
    invite_out.write_text(invite)
    invite_out.chmod(0o600)
    print("Restricted account-1002 lab SIPp scenarios prepared")

if __name__ == "__main__":
    main()
