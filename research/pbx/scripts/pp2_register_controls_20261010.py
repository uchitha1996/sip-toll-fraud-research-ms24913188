#!/usr/bin/env python3
"""PP2 four-case predeclared LAN-only nonauth REGISTER test. No PBX modifications."""
import csv,hashlib,json,os,shlex,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path("/home/astrix/sip-fraud-research")
sys.path.insert(0,str(ROOT/"scripts"))
from run_remote_sipp_challenges import sip_packets
from register_diversity_candidate_20261002 import replay as diversity_replay
OUT=ROOT/"datasets/pp2-registration-controls-20261010"
KEY=Path("/home/astrix/.ssh/sipp_lab_ed25519")
MANIFEST=OUT/"manifest.json"
CDR=Path("/var/log/asterisk/cdr-csv/Master.csv")
SENDER=ROOT/"scripts/pp2_bounded_register_sender_20261010.py"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def call(command,timeout=15,input=None):
    r=subprocess.run(command,capture_output=True,text=True,input=input,timeout=timeout)
    if r.returncode:raise RuntimeError("failed: "+str(command[0])+": "+r.stderr[-500:])
    return r.stdout
def ssh(cmd):
    return ["ssh","-T","-4","-i",str(KEY),"-o","BatchMode=yes","-o","IdentitiesOnly=yes",
      "-o","StrictHostKeyChecking=yes","-o","ConnectTimeout=6","sipp@172.16.200.68",cmd]
def idle():
    assert "0 active calls" in call(["asterisk","-rx","core show channels count"])
    for d in ("88001","88002"):
        assert "no existence" in call(["asterisk","-rx","dialplan show "+d+"@internal"])
def preflight(manifest):
    assert MANIFEST.exists() and SENDER.exists()
    assert len(manifest["case_descriptions"])==4
    assert manifest["absolute_max_register_requests"]==24
    assert manifest["requests_per_case"]==6 and manifest["no_credentials"] and manifest["no_invites"] and manifest["no_calls"]
    assert "172.16.200.81/24" in call(["ip","-4","-brief","address","show","wlan0"])
    assert "172.16.200.68" in call(ssh("ip -4 -brief address show wlan0"))
    idle()
    for name in ("1001","1002"):
        assert "Endpoint:" in call(["asterisk","-rx","pjsip show endpoint "+name])
    for name in ("9001","9002","9003","9004","9005","9006"):
        assert "Unable to find object" in call(["asterisk","-rx","pjsip show endpoint "+name])
    assert not (OUT/"summary.json").exists()
def run():
    os.umask(0o077)
    protocol=json.loads(MANIFEST.read_text());preflight(protocol)
    protocol_hash=sha(MANIFEST);sender_hash=sha(SENDER)
    results=[]
    for case in protocol["case_descriptions"]:
        sid=case["id"]
        assert sid in ("P001","P002","P003","P004") and len(case["targets"])==6
        if sha(MANIFEST)!=protocol_hash or sha(SENDER)!=sender_hash:
            raise RuntimeError("predeclared source/protocol changed after freeze")
        idle()
        p=OUT/sid
        p.mkdir(mode=0o700,exist_ok=False)
        before=CDR.read_bytes()
        (p/"cdr_before.csv").write_bytes(before)
        capture=None
        error=None
        try:
            with (p/"tcpdump.log").open("x") as log:
                capture=subprocess.Popen(["tcpdump","-i","wlan0","-n","-U","-s","0",
                    "-w",str(p/"traffic.pcap"),"udp and host 172.16.200.68 and port 5060"],
                    stdout=subprocess.DEVNULL,stderr=log)
            time.sleep(1)
            if capture.poll() is not None:raise RuntimeError("tcpdump failed")
            remote="python3 - "+shlex.quote(json.dumps(case["targets"]))
            r=call(ssh(remote),input=SENDER.read_text(),timeout=28)
            (p/"sender_responses.json").write_text(r)
            replies=json.loads(r)
            assert len(replies)==6
            time.sleep(1)
        except Exception as exc:
            error=str(exc)
        finally:
            if capture is not None:
                if capture.poll() is None:capture.send_signal(signal.SIGINT)
                capture.wait(timeout=8)
            (p/"cdr_after.csv").write_bytes(CDR.read_bytes())
        if error:
            (p/"ERROR.txt").write_text(error)
            raise RuntimeError(sid+" "+error)
        assert before==CDR.read_bytes(),"CDR unexpectedly changed"
        packet=sip_packets(p/"traffic.pcap",p/"sip_packets.csv")
        requests=[r for r in packet if r.get("sip.Method")=="REGISTER" and r.get("ip.src")=="172.16.200.68"]
        responses=[r for r in packet if r.get("sip.CSeq.method")=="REGISTER" and r.get("ip.src")=="172.16.200.81" and r.get("sip.Status-Code")]
        assert len(requests)==6 and len(responses)==6,(sid,len(requests),len(responses))
        assert sorted(r["sip.to.user"] for r in requests)==sorted(case["targets"])
        alerts=diversity_replay(p/"sip_packets.csv")
        unknown=[t for t in case["targets"] if t not in protocol["allowed_configured_accounts"]]
        item={"id":sid,"profile":case["profile"],"policy":case["policy"],"pcap_sha256":sha(p/"traffic.pcap"),
          "verified":True,"unique_targets":len(set(case["targets"])),"total_requests":len(requests),
          "responses":sorted(set(r["sip.Status-Code"] for r in responses)),
          "candidate_diversity_alert_count":len(alerts),"candidate_diversity_alerts":alerts,
          "requests_to_unconfigured_accounts":len(unknown),"answered_cdr_delta":0,
          "interpretation":"Policy status based on predeclared configured-account allowlist; NOT independently proven malicious intent"}
        (p/"verification.json").write_text(json.dumps(item,indent=2)+"\n")
        results.append(item)
        print("PASS",sid,"unique_targets",item["unique_targets"],"candidate_alerts",len(alerts),
             "policy_unknown_requests",len(unknown),flush=True)
    idle()
    summary={"experiment":"Fresh PP2 bounded lab REGISTER request tests, no INVITE/no authenticated changes",
      "manifest_sha256":protocol_hash,"sender_sha256":sender_hash,"runner_sha256":sha(Path(__file__)),
      "all_verified":len(results)==4 and all(x["verified"] for x in results),"cases":results,
      "limits":"Accounts 1001/1002 are known/configured; no 5-account legitimate NAT source tested; no fraud label; no ML retrain",
      "postflight":"PBX idle, temporary routes absent, CDR unchanged"}
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    print("FINAL PASS 4/4; read results in",OUT/"summary.json",flush=True)
if __name__=="__main__":run()
