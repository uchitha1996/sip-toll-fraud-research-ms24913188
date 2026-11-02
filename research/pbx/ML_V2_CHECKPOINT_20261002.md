# ML V2 development checkpoint — 2026-10-02

Six predeclared registration-only development controls DV2001–DV2006 captured and independently verified. Evidence: datasets/ml-v2-development-20261002/summary.json and manifest.json. Frozen model unchanged. Only DV2004/DV2005 satisfy its >=5 failures followed by success gate. This is not a new trained V2 model or held-out evaluation. No physical disconnect, retransmission, mixed traffic or policy-context tests completed in this batch. Zero active calls and temporary routes absent after completion.

Execution used imported unchanged lab_batch_runner.run with OUT redirected to the new directory and lab_process_batch.process(execute=False) with BASE/MANIFEST redirected. The original runner hash records the reused module, not this inline orchestration; preserve this distinction. Manifest preserves scenario parameters.
