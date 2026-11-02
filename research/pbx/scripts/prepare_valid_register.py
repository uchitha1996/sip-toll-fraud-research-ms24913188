#!/usr/bin/env python3
"""Prepare a restricted SIPp REGISTER scenario from the existing lab credential."""
import os
import re
from pathlib import Path

CONFIG = Path("/etc/asterisk/pjsip.conf")
TEMPLATE = Path("/home/astrix/sipp-lab/failed_password_register.xml")
OUT = Path("/home/astrix/sip-fraud-research/datasets/emulated-outbound-runs/.valid_register_1001.xml")
os.umask(0o077)
config = CONFIG.read_text()
blocks = re.findall(r"(?ms)^\[1001-auth\]\s*\n(.*?)(?=^\[|\Z)", config)
if len(blocks) != 1:
    raise SystemExit("Expected exactly one 1001 auth block")
values = re.findall(r"(?m)^password\s*=\s*(\S+)\s*$", blocks[0])
if len(values) != 1:
    raise SystemExit("Expected exactly one password assignment")
if not re.fullmatch(r"[^\s\]]{1,128}", values[0]):
    raise SystemExit("Credential has a SIPp keyword delimiter")
template = TEMPLATE.read_text()
if template.count("WrongLabPassword") != 1 or not template.count("1001"):
    raise SystemExit("Unexpected SIPp template")
template = template.replace("WrongLabPassword", values[0])
if template.count('<recv response="401"/>') != 1:
    raise SystemExit("Unexpected final response in SIPp template")
template = template.replace('<recv response="401"/>', '<recv response="200"/>')
OUT.write_text(template)
OUT.chmod(0o600)
print("Restricted valid-registration scenario prepared")
invite = Path("/home/astrix/sip-fraud-research/scripts/invite_auth_1001_template.xml").read_text()
if invite.count("LAB_PASSWORD_PLACEHOLDER") != 1:
    raise SystemExit("Unexpected INVITE template")
invite_out = OUT.with_name(".valid_invite_1001.xml")
invite_out.write_text(invite.replace("LAB_PASSWORD_PLACEHOLDER", values[0]))
invite_out.chmod(0o600)
print("Restricted valid-invite scenario prepared")
