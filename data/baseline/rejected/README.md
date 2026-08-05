# Rejected dry-run traces

These 2026-08-05 pilot artifacts are retained for auditability but excluded
from baseline analysis:

- `direct-03_wrong-channel.json` labeled a webpage injection as `chat_message`.
- `direct-01_flawed-render.json` and `direct-02_flawed-render.json` used the old
  renderer, which labeled content untrusted, added explanatory meta-text, and
  left unrelated action placeholders in the corpus template.
- `flawed-render_results.jsonl` is the corresponding two-record index.
- `*_injection-utility_gemini-3.6.json` are attack-independent utility traces
  from the same pilots. They became non-reusable when the recorded primary was
  switched to Gemini 3.5 Flash-Lite.

The attack traces were moved here so AgentDojo cannot reuse them when the
corrected goal-bound cases are run. No Gemini 3.6 cache remains under `raw/`.
