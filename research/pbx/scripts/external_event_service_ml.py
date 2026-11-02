#!/usr/bin/env python3
"""Loopback-only stage service with frozen causal review priority."""
import argparse
import json
import socketserver
import time
from causal_review_score import MLProgression, load_model

class Handler(socketserver.StreamRequestHandler):
    model = None
    def handle(self):
        engine = MLProgression(self.model)
        for line in self.rfile:
            received = time.perf_counter_ns()
            try:
                alerts = engine.accept(json.loads(line))
                result = {'ok': True, 'alerts': alerts,
                          'received_monotonic_ns': received,
                          'decided_monotonic_ns': time.perf_counter_ns()}
            except (ValueError, KeyError, TypeError) as exc:
                result = {'ok': False, 'error': type(exc).__name__ + ': ' + str(exc),
                          'received_monotonic_ns': received,
                          'decided_monotonic_ns': time.perf_counter_ns()}
            self.wfile.write((json.dumps(result, sort_keys=True) + '\n').encode())

class Service(socketserver.TCPServer):
    allow_reuse_address = True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=19056)
    parser.add_argument('--ml-model', required=True)
    args = parser.parse_args()
    assert 1024 < args.port < 65536
    Handler.model = load_model(args.ml_model)
    with Service(('127.0.0.1', args.port), Handler) as server:
        print(json.dumps({'state':'ready','bind':'127.0.0.1','port':args.port}), flush=True)
        server.serve_forever(poll_interval=0.02)

if __name__ == '__main__':
    main()
