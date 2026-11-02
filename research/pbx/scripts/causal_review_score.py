"""Pure-Python frozen stage-time logistic score; never suppress rule evidence."""
import hashlib
import json
import math
from pathlib import Path

from stream_progression_prototype import Progression

EXPECTED = ['failures_120s','peak_failures_10s','failure_span_s',
            'first_failure_to_success_s']

def load_model(path):
    path = Path(path)
    model = json.loads(path.read_text())
    assert model['feature_names'] == EXPECTED
    assert model['priority_thresholds'] == [.4, .6]
    assert len(model['mean']) == len(model['scale']) == len(model['coef']) == 4
    assert all(x > 0 for x in model['scale'])
    model['model_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return model

def score(model, values):
    z = model['intercept'] + sum(c*(v-m)/s for c,v,m,s in
        zip(model['coef'],values,model['mean'],model['scale']))
    return 1.0/(1.0+math.exp(-z))

class MLProgression(Progression):
    def __init__(self, model, policy=None):
        super().__init__(policy)
        self.model = model

    def accept(self, event):
        values = None
        if event['kind'] == 'REGISTER_SUCCESS':
            from stream_progression_prototype import epoch
            now = epoch(event['time_utc'])
            queue = self.failures[event['source_ip'], event.get('account','')]
            recent = [t for t,_ in queue if now-120 <= t <= now]
            if len(recent)>=5:
                peak = max(sum(t-10<=v<=t for v in recent) for t in recent)
                values = [len(recent),peak,round(max(recent)-min(recent),4),
                          round(now-min(recent),4)]
        alerts = super().accept(event)
        if values is not None:
            for alert in alerts:
                if alert['stage']=='SUSPECTED_COMPROMISE':
                    probability = score(self.model,values)
                    priority = ('LOWER' if probability < .4 else
                                'HIGHER' if probability >= .6 else 'REVIEW')
                    alert['ml_probability'] = probability
                    alert['ml_priority'] = priority
                    alert['ml_feature_values'] = values
                    alert['ml_model_sha256'] = self.model['model_sha256']
        return alerts
