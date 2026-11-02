import unittest
from datetime import datetime, timezone
from pathlib import Path
from common_evaluator import baseline, confusion, context_layer, frozen_online, load_v6, predictions

def stamp(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat().replace('+00:00', 'Z')

def event(t, kind, account='1001', method='REGISTER', status='', destination=''):
    return dict(time_utc=stamp(t), event_type=kind, entity='172.16.200.68',
                target=destination or account, method=method, status=status, call_id=f'call-{t}')

def packet(t, account='1001', destination='88001', method='INVITE'):
    return {'frame.time_epoch':str(t), 'ip.src':'172.16.200.68', 'ip.dst':'172.16.200.81',
            'sip.Method':method, 'sip.Status-Code':'', 'sip.CSeq.method':method,
            'sip.Call-ID':f'call-{t}', 'sip.from.user':account,
            'sip.to.user':destination, 'sip.r-uri.user':destination}

def policy():
    return dict(lab_source_ip='172.16.200.68', lab_destinations=['88001','88002'],
                accounts={a:dict(sources=['172.16.200.68'], registration_allowed=True,
                                allowed_destinations=[d]) for a,d in [('1001','88001'),('1002','88002')]},
                recovery_permissions=[dict(source_ip='172.16.200.68',account='1001',
                                           valid_from_utc=stamp(0),valid_until_utc=stamp(1000),
                                           max_confirmed_failures=8)])

class Checks(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).parent / 'frozen/progression_v6_development.py'
        if not source.exists():
            source = Path(__file__).parent.parent / 'inspected/progression_v6_development.py'
        self.v6 = load_v6(source)

    def recovery(self, account='1001', destination='88001'):
        timeline = [event(0,'REQUEST',account)]
        timeline += [event(t,'CONFIRMED_REJECTION',account) for t in range(1,7)]
        timeline += [event(7,'REGISTER_FINAL_RESPONSE',account,status='200'),
                     event(10,'REQUEST',account,method='INVITE',destination=destination)]
        return timeline, [packet(10,account,destination)]

    def test_initial_401_is_not_auth_failure(self):
        rows=[event(t,'REGISTER_FINAL_RESPONSE',status='401') for t in range(20)]
        self.assertEqual(baseline(rows,5),[])

    def test_accounts_sharing_ip_do_not_merge_failures(self):
        rows=[event(t,'CONFIRMED_REJECTION',account=a) for t,a in enumerate(['1001','1002']*3)]
        self.assertEqual(baseline(rows,5),[])

    def test_window_excludes_old_failures(self):
        rows=[event(t,'CONFIRMED_REJECTION') for t in [0,1,2,100,101]]
        self.assertEqual(baseline(rows,5),[])

    def test_frozen_v6_progression_and_lead_time(self):
        timeline,packets=self.recovery()
        result,_=predictions(timeline,packets,self.v6,policy())
        self.assertEqual(result['V6']['lead_time_seconds'],3)
        self.assertEqual([a['stage'] for a in result['V6']['alerts']],
                         ['SUSPECTED_COMPROMISE','SUSPECTED_OUTBOUND_ATTEMPT'])
        self.assertEqual(result['baseline_10']['predicted'],0)

    def test_allowed_recovery_keeps_stage_evidence_and_reduces_action(self):
        timeline,packets=self.recovery()
        result,decisions=predictions(timeline,packets,self.v6,policy())
        self.assertEqual(result['V6_context']['predicted'],0)
        self.assertTrue(decisions)
        self.assertTrue(all(d['disposition']=='authorized_recovery_review' for d in decisions))

    def test_forbidden_destination_detected_at_attempt_not_early(self):
        timeline,packets=self.recovery(destination='88002')
        result,_=predictions(timeline,packets,self.v6,policy())
        self.assertEqual(result['V6_context']['predicted'],1)
        self.assertEqual(result['V6_context']['lead_time_seconds'],0)
        self.assertEqual(result['V6_context']['alert_strictly_before_first_invite'],0)

    def test_unknown_policy_never_claims_authorized(self):
        timeline,packets=self.recovery(account='1002',destination='88002')
        result,_=predictions(timeline,packets,self.v6,policy())
        self.assertEqual(result['V6_context']['predicted'],1)

    def test_future_packets_cannot_change_recovery_decision(self):
        timeline,_=self.recovery()
        packets=[packet(100,account='1002',destination='88002')]
        stages=frozen_online(timeline[:-1],packets,self.v6,policy()['lab_destinations'])
        self.assertEqual([s['stage'] for s in stages],['SUSPECTED_COMPROMISE'])

    def test_identical_evidence_cannot_distinguish_hidden_roles(self):
        timeline,packets=self.recovery()
        left,_=predictions(timeline,packets,self.v6,policy())
        right,_=predictions(timeline,packets,self.v6,policy())
        self.assertEqual(left,right)
        self.assertEqual(left['V6_context']['predicted'],0)

    def test_undefined_metric_is_null(self):
        m=confusion([dict(truth=0,predicted=0)])
        self.assertIsNone(m['recall'])
        self.assertIsNone(m['balanced_accuracy'])

if __name__=='__main__':
    unittest.main()
