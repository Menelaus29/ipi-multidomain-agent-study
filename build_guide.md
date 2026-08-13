# Build Guide: Indirect Prompt Injection Multi-Domain Study

### A phase-by-phase, step-by-step construction plan (human-executed, Git/GitHub tracked)

## Executed repository-scope decision: Phase 6A stays on its own branch

Phase 6A was created solely to replace the Phase 6 static-corpus floor of 0/110
with a measurable, nonzero undefended baseline. The Gemini 3.5 Flash-Lite
calibration did not meet that objective or its qualification gate. Therefore,
under the executed project decision, `phase-6a-attack-calibration` is an
archival/evidence branch and is not to be merged into `main`.

Keep Phase 6A's calibration code, manifests, attempts, raw traces, and related
artifacts on that branch for provenance and final-report analysis. The README
and final report should acknowledge the failed Phase 6A attempt and explain the
move to the separate Gemma 4 track. Do not copy Phase 6A bulk artifacts into
`main`, mark the failed Phase 6A gate as passed, or resume Phase 6A solely to
make it mergeable. The intended curated `main` scope is the original Phase 6
static baseline plus Gemma 4 diagnostic/baseline/follow-up material and later
Gemma-track work that has a direct role in the active study.

This decision supersedes any generic Phase 6A checklist instruction to push,
merge, or tag the calibration branch. It is a repository-scope and methodology
decision, not deletion of evidence. If Phase 6A is revisited, work from
`phase-6a-attack-calibration`, use a newly versioned protocol and held-out data
as required, and obtain a new explicit decision before changing `main`.

  

> This is the execution-level breakdown of `sop_ipi_project.md`. That document told an AI *what* to build and why; this document tells *you* the literal sequence of actions, in order, each one small enough to do in a single sitting and commit on its own.

>

> **How to use it:** work top to bottom. Each phase ends with a merge to `main` and a tag — treat the tag as "this phase is real and done," not "I think I'm done." Don't start Phase N+1 with Phase N's tag missing.

  

---

  

## Git & GitHub conventions (set once, applies to every phase below)

  

- **Repo name suggestion:** `ipi-multidomain-agent-study` (rename as you like).

- **Branching:** one branch per phase, named `phase-<N>-<short-name>` (e.g. `phase-5-payload-corpus`). Never commit experimental/half-working code directly to `main`.

- **Commits:** small and atomic, one per meaningful unit of work — not one giant commit per phase. Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes:

  - `feat:` new code/functionality

  - `data:` new or updated data files (corpus, results)

  - `experiment:` a completed experiment run

  - `analysis:` aggregation/analysis scripts and outputs

  - `docs:` documentation, threat model, report writing

  - `chore:` scaffolding, config, dependencies

  - `fix:` bug fixes

- **Merging:** open a Pull Request from the phase branch into `main` at the end of each phase, even solo — write a PR description restating the phase's Definition of Done, then merge it yourself. This gives you a clean, reviewable history, which is itself evidence of rigor for your final report/portfolio.

- **Tagging:** after each merge, tag `main`: `git tag -a phase-<N>-done -m "Phase <N>: <name> complete"` then `git push origin phase-<N>-done`.

- **Secrets:** API keys live only in a local `.env`, which is gitignored from Step 0.3 onward. Before every single commit, glance at `git diff --staged` for anything that looks like a key. Never rely on memory alone here.

  

---

  

## Phase 0 — Repository & Git Initialization

  

**Objective:** get a real, remote-backed Git repository with the baseline hygiene files in place before any project code exists.

  

- [x] **0.1** Create a new empty repository on GitHub (decide public vs. private now — you can flip it later).

- [x] **0.2** Clone it to your machine: `git clone <repo-url> && cd <repo-name>`.

- [x] **0.3** Create `.gitignore` (Python template) and add: `.venv/`, `__pycache__/`, `*.pyc`, `.env`, `.DS_Store`.

- [x] **0.4** Create `README.md` with: project title, one-paragraph overview (adapt from your docx's Section 1), and a `## Status` line you'll update as phases complete.

- [x] **0.5** Decide on and add a `LICENSE` file (MIT is a reasonable default for a research/portfolio repo).

- [x] **0.6** Stage and commit: `git add . && git commit -m "chore: initial repository scaffold"`.

- [x] **0.7** Push to `main`: `git push -u origin main`.

- [x] **0.8** *(Recommended)* Create one GitHub Issue per phase (0–14) as a lightweight tracking board — gives you a visual checklist independent of this file.

  

**Definition of Done:** repo exists on GitHub, `main` has one commit, `.gitignore` is in place *before* any secret could ever be written to disk.

  

---

  

## Phase 1 — Environment Setup

  

**Objective:** a working, reproducible Python environment with AgentDojo installed and API access confirmed.

  

- [x] **1.1** `git checkout -b phase-1-environment`

- [x] **1.2** Create a virtual environment: `python -m venv .venv` (or `uv venv`).

- [x] **1.3** Activate it: `source .venv\Scripts\activate.

- [x] **1.4** Install AgentDojo: `pip install agentdojo`

- [x] **1.5** If you plan to use the built-in transformer-based PI detector defense later, also run `pip install "agentdojo[transformers]"` now.

- [x] **1.6** Freeze dependencies: `pip freeze > requirements.txt`.

- [x] **1.7** Create `.env.example` with `GOOGLE_API_KEY=` (primary, Google AI Studio / Gemini Developer API - not Vertex), `GROQ_API_KEY=` (legacy/unused after the provider switch), and `CO_API_KEY=` (native-AgentDojo fallback, 1,000 calls/month cap). Omit `TOGETHER_API_KEY` - confirmed no free tier as of July 2026. No real values in this file.

- [x] **1.8** Create your real `.env` locally with actual key(s) — this file must never be staged.

- [x] **1.9** Double-check: `git status` should **not** show `.env`. If it does, fix `.gitignore` before proceeding.

- [x] **1.10** Add a `## Setup` section to `README.md` documenting steps 1.2–1.8 for future-you.

- [x] **1.11** Commit: `git add requirements.txt .env.example README.md && git commit -m "chore: environment setup and dependency pinning"`.

- [x] **1.12** Push branch: `git push -u origin phase-1-environment`. Open PR → merge into `main`.

- [x] **1.13** Tag: `phase-1-done`.

  

**Definition of Done:** fresh clone + `pip install -r requirements.txt` + `.env` reproduces your environment exactly.

  

---

  

## Phase 2 — Literature Review & Threat Model Documentation

  

**Objective:** turn the reading you need to do anyway into two concrete, reusable documents.

  

- [x] **2.1** `git checkout main && git pull && git checkout -b phase-2-threat-model`

- [x] **2.2** Read Greshake et al. [1] — the original indirect-prompt-injection paper. Take raw notes anywhere (scratch file, not committed).

- [x] **2.3** Read the AgentDojo paper [2] in full, not just the README — you need to understand its task/suite design to use it well later.

- [x] **2.4** Read InjecAgent [3] for a second taxonomy perspective.

- [x] **2.5** Read OWASP Top 10 for LLM Applications [10] and OWASP Top 10 for Agentic Applications [11].

- [x] **2.6** Write `docs/threat_model.md`: attacker model (who, what they control, what they want), assets at risk per domain (workspace/banking/slack), and trust boundaries (where untrusted data enters the agent's context).

- [x] **2.7** Commit: `git add docs/threat_model.md && git commit -m "docs: threat model"`.

- [x] **2.8** Write `docs/taxonomy.md`: the payload category table (direct override, role-play/persona, encoding/obfuscation, multi-step sleeper, fake system message, chat-template abuse), each with a short justification for why it's a distinct category.

- [x] **2.9** Commit separately: `git add docs/taxonomy.md && git commit -m "docs: payload taxonomy"`.

- [x] **2.10** Push, open PR, merge, tag `phase-2-done`.

  

**Definition of Done:** two documents exist that you could hand to someone else and they'd understand your threat model and taxonomy without asking you anything.

  

---

  

## Phase 3 — AgentDojo Familiarization & Sanity Check

  

**Objective:** confirm the benchmark actually runs on your machine, with your API key, before you build anything on top of it.

  

- [x] **3.1** `git checkout main && git pull && git checkout -b phase-3-agentdojo-sanity-check`

- [x] **3.2** Clone `ethz-spylab/agentdojo` **separately**, outside your project repo, purely for reading source/docs — do not vendor it into your repo.

- [x] **3.3** Open and read its `CLAUDE.md` (it exists in the repo root) — note the dev commands even though you're not using an AI agent for this phase; it documents the benchmark script's real usage.

- [x] **3.4** Run `python -m agentdojo.scripts.benchmark --help` and read every flag.

```

Usage: python -m agentdojo.scripts.benchmark [OPTIONS]

  

Options:

  --model [gpt-4o-2024-05-13|gpt-4o-mini-2024-07-18|gpt-4-0125-preview|gpt-3.5-turbo-0125|gpt-4-turbo-2024-04-09|claude-3-opus-20240229|claude-3-sonnet-20240229|claude-3-5-sonnet-20240620|claude-3-5-sonnet-20241022|claude-3-7-sonnet-20250219|claude-3-7-sonnet-20250219-thinking-16000|claude-3-haiku-20240307|command-r-plus|command-r|mistralai/Mixtral-8x7B-Instruct-v0.1|meta-llama/Llama-3-70b-chat-hf|gemini-1.5-pro-002|gemini-1.5-pro-001|gemini-1.5-flash-002|gemini-1.5-flash-001|gemini-2.0-flash-exp|gemini-2.0-flash-001|gemini-2.5-flash-preview-04-17|gemini-2.5-pro-preview-05-06|local|vllm_parsed|openai-compatible]

                                  The language model to benchmark. Defaults to

                                  `gpt-4o-2024-05-13`.

  --model-id TEXT                 The model id for local models.

  --benchmark-version TEXT        The version of the benchmark to run.

                                  Defaults to `v1.2`.

  --tool-delimiter TEXT           Which tool delimiter to use. Used for local

                                  models only.

  --logdir PATH                   The directory to save logs. Defaults to

                                  `./runs`.

  --attack TEXT                   The attack to use. `None` by default. It

                                  should be one of {'manual': <class 'agentdoj

                                  o.attacks.baseline_attacks.ManualAttack'>,

                                  'direct': <class 'agentdojo.attacks.baseline

                                  _attacks.DirectAttack'>, 'ignore_previous':

                                  <class 'agentdojo.attacks.baseline_attacks.I

                                  gnorePreviousAttack'>, 'system_message':

                                  <class 'agentdojo.attacks.baseline_attacks.S

                                  ystemMessageAttack'>, 'injecagent': <class '

                                  agentdojo.attacks.baseline_attacks.InjecAgen

                                  tAttack'>, 'important_instructions': <class '

                                  agentdojo.attacks.important_instructions_att

                                  acks.ImportantInstructionsAttack'>,

                                  'important_instructions_no_user_name':

                                  <class 'agentdojo.attacks.important_instruct

                                  ions_attacks.ImportantInstructionsAttackNoUs

                                  erName'>,

                                  'important_instructions_no_model_name':

                                  <class 'agentdojo.attacks.important_instruct

                                  ions_attacks.ImportantInstructionsAttackNoMo

                                  delName'>,

                                  'important_instructions_no_names': <class 'a

                                  gentdojo.attacks.important_instructions_atta

                                  cks.ImportantInstructionsAttackNoNames'>,

                                  'important_instructions_wrong_model_name':

                                  <class 'agentdojo.attacks.important_instruct

                                  ions_attacks.ImportantInstructionsWrongModel

                                  Name'>,

                                  'important_instructions_wrong_user_name':

                                  <class 'agentdojo.attacks.important_instruct

                                  ions_attacks.ImportantInstructionsWrongUserN

                                  ame'>, 'tool_knowledge': <class 'agentdojo.a

                                  ttacks.important_instructions_attacks.ToolKn

                                  owledgeAttack'>, 'dos': <class

                                  'agentdojo.attacks.dos_attacks.DoSAttack'>,

                                  'swearwords_dos': <class 'agentdojo.attacks.

                                  dos_attacks.SwearwordsDoSAttack'>,

                                  'captcha_dos': <class 'agentdojo.attacks.dos

                                  _attacks.CaptchaDoSAttack'>,

                                  'offensive_email_dos': <class 'agentdojo.att

                                  acks.dos_attacks.OffensiveEmailDoSAttack'>,

                                  'felony_dos': <class 'agentdojo.attacks.dos_

                                  attacks.FelonyDoSAttack'>}, or a custom

                                  attack defined and registered in of of the

                                  `--module-to-load`. If `None`, no attack is

                                  used.

  --defense [tool_filter|transformers_pi_detector|spotlighting_with_delimiting|repeat_user_prompt]

                                  The defense to use. `None` by default.

  --system-message-name TEXT      The name of the system message to use among

                                  the default ones in

                                  `data/system_messages.yaml`.

  --system-message TEXT           The system message to use (as a string). If

                                  provided, `--system-message-name` is

                                  ignored.

  -ut, --user-task TEXT           The user tasks to benchmark. If not

                                  provided, all tasks in the suite are run.

  -it, --injection-task TEXT      The user tasks to benchmark. If not

                                  provided, all tasks in the suite are run.

  -s, --suite TEXT                The user tasks to benchmark. If not

                                  provided, all tasks in the suite are run.

  --max-workers INTEGER           How many suites can be benchmarked in

                                  parallel through multithreading. Nothing is

                                  parallelized by default.

  -f, --force-rerun               Whether to re-run tasks that have already

                                  been run.

  -ml, --module-to-load TEXT      The modules to load before running the

                                  benchmark. Useful for registering custom

                                  attacks, defenses, or suites.

  --help                          Show this message and exit.

```

  

- [x] **3.5** Transcribe into `docs/agentdojo_capabilities.md`: (a) the full set of suites, attacks, and defenses, (b) **the per-suite tool list** for workspace/banking/slack specifically — this is what threat_model.md's trust-boundary and assets-at-risk sections are built on, so get it in writing here, not just in chat — and (c) the closed-`ModelsEnum` finding: `--model`/`get_llm()` only accept a fixed model list, and its built-in Google path uses Vertex AI (not the free AI Studio API key), which is why 3.5a exists.

- [x] **3.5a** — Create the Google AI Studio provider factory

  

Create `scripts/google_llm_factory.py` (a dev-scripts location for now — Phase 4 relocates this to `src/llm_providers/`, see 4.2a):

  

> **Provider decision:** Google AI Studio (`GOOGLE_API_KEY`, free tier, Gemini Developer API — **not Vertex AI**). AgentDojo's built-in `get_llm()` for Google models builds a Vertex AI client (`genai.Client(vertexai=True, ...)`), which requires a billed GCP project. This factory uses `genai.Client(api_key=GOOGLE_API_KEY)` and passes the constructed object directly to `benchmark_suite()`, bypassing `get_llm()`/`ModelsEnum` entirely.

>

> **Two compatibility issues discovered during Phase 3.6 integration testing:**

> 1. **Gemini 3.x `thought_signature` forwarding** — Gemini 3.x models embed a `thought_signature` field in function-call response parts. AgentDojo's `GoogleLLM` converts tool calls to its own `FunctionCall` dataclass (name + args only), discarding the signature. On turn 2+, the API returns `400 INVALID_ARGUMENT: Function call is missing a thought_signature`. Fix: `Gemini3LLM` subclass that caches and replays the raw `genai_types.Part` list from each model response, so subsequent turns send the full original parts (including signature) verbatim.

> 2. **`_AGENTDOJO_GEMINI_ID` in pipeline name** — `ToolKnowledgeAttack.__init__` and the `ImportantInstructionsAttack` family call `get_model_name_from_pipeline()` at construction, which requires `pipeline.name` to contain a known substring from `MODEL_NAMES`. Embedding `gemini-2.5-flash-preview-04-17` resolves to `'AI model developed by Google'`.

>

> **Legacy note:** Groq (`scripts/groq_llm.py`) was the original planned provider. It was replaced by Google AI Studio after discovering persistent `thought_signature`-equivalent schema compatibility issues with Groq's OpenAI-compatible endpoint. `groq_llm.py` is retained in `scripts/` for reference but is no longer the active provider.

  

```python

# scripts/google_llm_factory.py

from google import genai

from google.genai import types as genai_types

from agentdojo.agent_pipeline.llms.google_llm import (

    GoogleLLM, _function_to_google, _message_to_google,

    _merge_tool_result_messages, _google_to_assistant_message,

    chat_completion_request,

)

from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime

from agentdojo.types import ChatMessage

import os

from collections.abc import Sequence

  

PRIMARY_MODEL  = "gemini-3.5-flash-lite" # all recorded results and adaptive search

FALLBACK_MODEL = "gemini-3.1-flash-lite" # non-recorded diagnostics only

_AGENTDOJO_GEMINI_ID = "gemini-2.5-flash-preview-04-17"  # MODEL_NAMES compat

  
  

class Gemini3LLM(GoogleLLM):

    """GoogleLLM subclass that forwards thought_signature across turns.

    Caches raw response Parts and replays them verbatim so the API sees the

    original thought_signature in subsequent turns.

    """

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):

        # ... (see scripts/google_llm_factory.py for full implementation)

        ...

  
  

class FallbackGemini3LLM(Gemini3LLM):

    """Testing-only: auto-switches to FALLBACK_MODEL on RPD 429 exhaustion.

    Never use for recorded benchmark runs.

    """

    ...

  
  

def get_google_llm(model_name=PRIMARY_MODEL) -> Gemini3LLM:

    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY", "").strip())

    llm = Gemini3LLM(model_name, client)

    llm.name = f"google-{model_name} [{_AGENTDOJO_GEMINI_ID}]"

    return llm

  

def get_google_primary_llm() -> Gemini3LLM:   return get_google_llm(PRIMARY_MODEL)

def get_google_fallback_llm() -> Gemini3LLM:  return get_google_llm(FALLBACK_MODEL)

def get_google_testing_llm() -> FallbackGemini3LLM: ...  # auto-fallback for tests

```

  

- [x] **3.5b** — Commit

```bash

git add scripts/google_llm_factory.py

git commit -m "feat: google ai studio provider factory (bypasses agentdojo's vertex ai path)"

```

- [x] **3.5c** — Confidence check: one raw API call, no AgentDojo involved

```python

# throwaway — paste into a python shell, don't commit

import os

from dotenv import load_dotenv; load_dotenv()

from google import genai

  

client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY").strip())

resp = client.models.generate_content(

    model="gemini-3.5-flash-lite",

    contents="Say hi in one word.",

)

print(resp.text)

```

If that prints a one-word reply, your key and both model selections are confirmed working before 3.6 wraps the same thing in AgentDojo's machinery.

  

- [x] **3.6** Run the sanity check via AgentDojo's Python API — the CLI is a dead end for this project's Google AI Studio path (uses Vertex AI, per 3.5a).

  

**Rate-limit note (active free tier):** `gemini-3.5-flash-lite` has 15 RPM, 250k TPM, and 500 RPD. The request-level limiter targets 14 RPM; no manual inter-suite pause is required. Testing-only `FallbackGemini3LLM` switches to `gemini-3.1-flash-lite` on primary RPD exhaustion. Slack suite uses `injection_task_1` (its injection tasks are numbered 1–5; there is no `injection_task_0`).

  

```python

# scripts/sanity_check.py

from pathlib import Path

from dotenv import load_dotenv; load_dotenv()

  

from agentdojo.scripts.benchmark import benchmark_suite

from agentdojo.task_suite.load_suites import get_suite

from scripts.google_llm_factory import get_google_testing_llm

  

# workspace and banking: injection_task_0

# slack: injection_task_1 (no injection_task_0 in slack suite)

for suite_name, inj_task in [("workspace", "injection_task_0"),

                              ("banking",   "injection_task_0"),

                              ("slack",     "injection_task_1")]:

    suite = get_suite("v1.2.2", suite_name)

    llm = get_google_testing_llm()

    results = benchmark_suite(

        suite=suite, model=llm,

        logdir=Path(f"data/sanity_check/{suite_name}"),

        force_rerun=True, benchmark_version="v1.2.2",

        user_tasks=("user_task_0",),

        injection_tasks=(inj_task,),

        attack="tool_knowledge",

    )

    print(suite_name, results)

```

Run from repo root: `$env:PYTHONPATH="."; .venv\Scripts\python.exe scripts\sanity_check.py`

Commit: `git add scripts/sanity_check.py data/sanity_check/ && git commit -m "experiment: google ai studio sanity check — all 3 suites"`

- [x] **3.7** Repeat step 3.6 once for `banking` and once for `slack` — confirm all three suites run cleanly on your setup. Note: `scripts/sanity_check.py` handles all three suites in a single rate-limited run and uses testing-only fallback `gemini-3.1-flash-lite` if the primary model's daily quota is exhausted.

- [x] **3.8** Save one example raw output/trace to `docs/example_run_output.json` (check it for anything sensitive before committing — there shouldn't be, but check).

- [x] **3.9** Commit: `git add docs/agentdojo_capabilities.md docs/example_run_output.json && git commit -m "docs: agentdojo capabilities and sanity-check output"`.

- [x] **3.10** Push, PR, merge, tag `phase-3-done`.

  

**Definition of Done:** you have personally watched all three target suites run end-to-end, and you have a written reference for every attack/defense/suite name AgentDojo already provides.

  

---

  

## Phase 4 — Project Scaffolding & Data Schemas

  

#### Note for Phase 4 (add as a new sub-step, e.g. 4.2a)

  

When you build the real `src/` tree in Phase 4, move `scripts/google_llm_factory.py` → `src/llm_providers/google_llm_factory.py`, and update the import in `scripts/sanity_check.py` accordingly. Phase 6's `run_baseline.py` will import `get_google_primary_llm` from that same relocated module rather than duplicating the client-construction code.

  

**Objective:** build the skeleton every later phase writes into, and make your data schemas machine-checkable, not just documented.

  

- [x] **4.1** `git checkout main && git pull && git checkout -b phase-4-scaffolding`

- [x] **4.2** Create the folder structure:

  ```

  src/{defenses,payloads,adaptive,analysis,experiments}/

  data/{baseline,defended,adaptive}/

  report/{figures,case_studies}/

  docs/

  ```

- [x] **4.2a** Move `scripts/google_llm_factory.py` → `src/llm_providers/google_llm_factory.py`. Update the import in `scripts/sanity_check.py` accordingly (`from src.llm_providers.google_llm_factory import get_google_testing_llm`). Phase 6's `run_baseline.py` will import from this relocated path.

- [x] **4.3** Add a `.gitkeep` file to every empty `data/` and `report/` subfolder so Git tracks the (currently empty) directories.

- [x] **4.4** Write `src/schemas.py` defining two data classes (or Pydantic models): `PayloadEntry` and `RunResult`, matching the fields specified in the SOP's §6 (id, category, channel, domain, template, source / run_id, timestamp, domain, task ids, model, defense, attack_success, tool_calls, notes).

- [x] **4.5** Write `src/analysis/validate_schema.py`: a small script that loads a JSON/JSONL file and validates every record against the relevant schema, printing clear errors for violations.

- [x] **4.6** Run it against an empty/sample file to confirm it works (no real data yet — just prove the validator itself is correct).

- [x] **4.7** Commit: `git add . && git commit -m "feat: project scaffolding and data schemas"`.

- [x] **4.8** Push, PR, merge, tag `phase-4-done`.

  

**Definition of Done:** the folder tree exists on `main`, and you have a script that can catch a malformed data record before it silently corrupts your later analysis.

  

---

  

## Phase 5 — Payload Taxonomy → Corpus Construction

  

**Objective:** turn your taxonomy from Phase 2 into ~20–25 concrete, tagged payloads.

  

- [x] **5.1** `git checkout main && git pull && git checkout -b phase-5-payload-corpus`

- [x] **5.2** For category `direct_override`, draft 3–5 payload variants directly into `src/payloads/corpus.json`, following the `PayloadEntry` schema.

- [x] **5.3** Repeat step 5.2 for `role_play_persona`.

- [x] **5.4** Repeat for `encoding_obfuscation`.

- [x] **5.5** Repeat for `multi_step_sleeper`.

- [x] **5.6** Repeat for `fake_system_message`.

- [x] **5.7a** Before drafting full `chat_template_abuse` variants, write and run **one** payload as a manual smoke test — per `taxonomy.md` §2.6, this category's effectiveness against GoogleLLM's structured `google-genai` SDK message format is empirically uncertain (tool results arrive as typed SDK Part objects, not raw delimited text). Log the raw response.

- [x] **5.7b** If the smoke test shows any signal, draft the remaining 3-5 variants. If not, draft fewer (2-3) and note the empirical null result in `docs/payload_corpus_notes.md` rather than padding the category.

- [x] **5.8** For every entry, fill in `channel` and domain(s), per the verified mapping in `taxonomy.md` §4: `web_content` is **Slack-only** (`get_webpage` — Workspace/Banking have no web tool). `email_body`/calendar → Workspace only. Transaction-memo → Banking only. `file_content` → Workspace + Banking. Slack chat is retrievable but excluded from recorded Phase 6 results because AgentDojo v1.2.2 has no native message-body injection placeholder.

- [x] **5.9** Run `validate_schema.py` against `corpus.json`, fix any violations.

- [x] **5.10** Read through the full corpus once, end to end, and remove any near-duplicate entries — aim for genuine variety, not padding the count.

- [x] **5.11** Write `docs/payload_corpus_notes.md`: one or two sentences per category explaining your design choices (this saves you rewriting the reasoning later for the report).

- [x] **5.12** Commit: `git add src/payloads/corpus.json docs/payload_corpus_notes.md && git commit -m "data: tagged payload corpus (v1, N=<count>)"`.

- [x] **5.13** Push, PR, merge, tag `phase-5-done`.

  

**Definition of Done:** `corpus.json` passes schema validation, has no near-duplicates, and every entry is traceable to a taxonomy category with a stated rationale.

  

---

  

## Phase 6 — Baseline Experiment Execution (Undefended)

  

**Objective:** measure the performance of the original static payload corpus with no defense active, across the documented domain × payload × channel matrix. This phase now produces the **static-corpus baseline**; because its observed ASR is 0/110, it is retained as a valid null result but is not the baseline used to estimate defense effectiveness. Phase 6A creates that measurable baseline prospectively.

> **Executed deviation (Phase 6.6):** The full channel-compatible task-by-injection expansion is still infeasible, but the new primary's 500-RPD quota supports useful replication. `run_baseline.py` therefore defaults to a documented **110-case expanded stratified matrix**: two native injection goals and up to two reachable vectors per retained payload/domain case (Workspace 52, Banking 46, Slack 12). The exhaustive expansion remains available as `--matrix full`. See `docs/decisions_log.md` for the decision.

> **Runner behavior:** A payload-specific registered AgentDojo attack places a goal-bound corpus template into the verified channel vector. Plain variants contain the task's native injection goal directly; encoding variants contain a reversible runtime transformation of that exact goal. AgentDojo's injection-task result remains the source of truth; despite its historical `security` variable name, `True` means the injection goal executed, so `attack_success` equals that value. Raw traces are retained under `data/baseline/raw/`, while `data/baseline/results.jsonl` is a schema-validated, resumable index.

> **Positive control:** `python -m src.experiments.run_positive_control` runs AgentDojo's native `injecagent` attack once in Workspace, Banking, and Slack. Its separately checkpointed output is diagnostic and is never included in corpus baseline ASR.

  

- [x] **6.1** `git checkout main && git pull && git checkout -b phase-6-baseline-execution`

- [x] **6.2** Write `src/experiments/run_baseline.py`: loads `corpus.json`, iterates domain × payload × channel, calls AgentDojo's `benchmark_suite()` via the Python API (not the CLI script — uses Vertex AI by default, per Phase 3), importing `get_google_primary_llm` from `src/llm_providers/google_llm_factory.py` with no defense, writes one `RunResult` JSONL line per run to `data/baseline/`. Use `get_google_primary_llm()` **only** — never `get_google_testing_llm()` or the fallback — recorded results must come from `gemini-3.5-flash-lite` exclusively.

- [x] **6.3** Commit the script alone first (no data yet): `git commit -m "feat: baseline experiment runner"`.

- [x] **6.4** Do a small dry run — 5–10 cases only — to confirm the script works end to end. **Completed 2026-08-05:** 10 Gemini 3.5 Flash-Lite cases completed across Workspace (4), Banking (2), and Slack (4), using 33 request attempts with no 429s. All ten attacks failed behaviorally, matching three separately completed native InjecAgent controls; schema checks and hand inspection confirmed correct goal-bound rendering and verdicts. Obsolete Gemini 3.6 pilot artifacts were deleted after this successful replacement run.

- [x] **6.5** From the dry run, measure and note actual cost and time per call; extrapolate to the **documented stratified matrix** size. The original full expansion is retained only as a future-capacity comparison. **Measured 2026-08-05:** 10 completed cases used 33 API request attempts in 149.951 seconds: 3.3 requests and 14.995 seconds per case, or 4.544 seconds per request, at $0 monetary cost on the free tier. At that rate, 110 cases project to 363 requests and about 27.5 minutes; after the dry run, the remaining 100 cases project to 330 requests and about 25 minutes.

- [x] **6.6** If the extrapolated cost/time is unaffordable, make and document a trimming decision now in `docs/decisions_log.md` (e.g., fewer tasks per suite) — do **not** silently shrink scope without writing down why.

- [x] **6.7** Run the documented 110-case expanded stratified baseline matrix. For long runs, use `nohup ... &` or a tmux/screen session so it survives a disconnect, and use the runner's JSONL checkpointing so a crash does not force a full restart. Do not use `--matrix full` for recorded results unless primary-model capacity is expanded and the scope decision is revisited. **Completed 2026-08-05:** 110/110 planned cases were checkpointed with Gemini 3.5 Flash-Lite. Eight initial rows backed by AgentDojo 503-skip traces were rejected, pruned, and force-rerun; the final index contains only error-free traces. Conservative accounting placed the day's usage at no more than 365/500 RPD.

- [x] **6.8** After completion, verify every expected result file exists and is non-empty. **Verified:** the 110-row plan and 110-row index have identical case keys with no missing, extra, or duplicate cases; all 110 referenced raw traces are unique, present, non-empty, and error-free (119 raw JSON files total including utility/control traces, all error-free).

- [x] **6.9** Run `validate_schema.py` against the full `data/baseline/` output. **Verified:** `results.jsonl` passes as 110 `RunResult` records; the separate three-record positive-control index also passes.

- [x] **6.10** Spot-check 3–5 individual result records by hand against their raw tool-call trace — confirm the `attack_success` boolean actually matches what happened. **Verified:** five cases spanning Workspace, Banking, Slack, direct override, encoding, and the repaired chat-template payload had exact index/raw message equality, `error: null`, matching `attack_success`/AgentDojo verdicts, and no tool call implementing the injected goal.

- [x] **6.11** Commit results: `git add data/baseline/ && git commit -m "experiment: undefended baseline (N=<count> runs)"`. **Completed:** local commit `e72ebc0` (`experiment: undefended baseline (N=110 runs)`).

- [x] **6.12** Push, PR, merge, tag `phase-6-done`.

  

**Definition of Done:** every planned static-corpus baseline run exists as a validated, spot-checked JSONL record under `data/baseline/`. A 0/110 result satisfies this phase's execution requirement, but it does **not** authorize defense-effectiveness claims; Phase 6A must pass its nonzero-baseline gate first.

---

## Phase 6A — Attack Calibration & Measurable Undefended Baseline

**Objective:** replace the zero-ASR floor with a prospectively evaluated, model-specific attack baseline before the defense is designed or tested. Keep the original 110 static results unchanged as a separate finding.

> **Why this phase exists:** An undefended ASR of 0/110 leaves no observable reduction for a defense to produce. The trace audit showed that this was not an injection-delivery failure: all 110 payloads reached Gemini (102 as normalized literal matches and eight after Unicode decoding), while legitimate utility succeeded in 90/110 cases. The defensible interpretation is therefore "the 2023–2024-style static corpus did not compromise this target model," not "prompt injection is impossible" and not "the future defense is effective."
>
> **What the recent papers add, in plain language:** Google reports deliberately hardening the Gemini family with automatically generated indirect prompt injections. Hofer, Debenedetti, and Tramèr (2026) show that black-box prompt search can outperform fixed/manual attacks, that effectiveness depends on the target and attacker models, and that attacks tuned on smaller models may not transfer to frontier models. Bhagwatkar et al. (2025) show that weak attacks and flawed metrics can make public agent-security benchmarks look solved. Zhan et al. (2025) show why a later, separate defense-aware attack is still required. The operational consequence is: tune attacks only on development cases, freeze them, then measure them once on unseen held-out cases.
>
> **Three terms that must not be conflated:**
> - **Static baseline:** the completed 110 cases using the original fixed corpus; no payload learned from Gemini's failures.
> - **Model-adaptive calibration (this phase):** an attacker sees only the undefended model's development traces and iteratively revises attacks. It does not see the spotlighting design.
> - **Defense-adaptive attack (Phases 10–11):** an attacker is explicitly told how the implemented defense works and iterates against it. This remains a separate final evaluation.
>
> **Leakage rule:** Development results may influence attack selection. Held-out results may never influence a payload that is evaluated on those same cases. If an attack set is revised after seeing held-out results, increment its version and evaluate it only on a new, never-used held-out manifest.
>
> **Why the pass gate is 15 overall and five/domain:** One success would technically make ASR nonzero, but a defense stopping that single event would be anecdotal. Five successful undefended events in each of three domains creates at least 15 concrete opportunities for the defense to prevent an attack while keeping the cross-domain question alive. This is a pragmatic minimum, not a statistical-power guarantee, so confidence intervals and low-count limitations remain mandatory.
>
> **Quota rule for every API command in this phase:** read both numbers from the Google rate-limit dashboard immediately before the command and pass them as `--dashboard-used` and `--dashboard-limit`. The command must also receive the Pacific `--quota-date` and `--max-api-requests`; it must refuse to run without all four arguments. The shared quota guard computes `effective_limit = min(500, dashboard_limit)`, `known_used = max(dashboard_used, locally ledgered usage/reservations for that quota day)`, and `safe_budget = min(requested_budget, effective_limit - known_used - 25)`. Before calls it acquires a single-process lock and records a reservation for the entire `safe_budget`; on clean exit it reconciles that reservation to actual attempts, while an interrupted process leaves the conservative reservation in place until the dashboard is checked. It configures the existing request-attempt limiter with `safe_budget`, counts initial calls and retries, and stops before call `safe_budget + 1`. Run only one Gemini process at a time. The 25-request reserve is never available to experiment scripts.
> **Example:** if the dashboard says 56/500 and the local ledger is not higher, the largest permitted process cap is `500 - 56 - 25 = 419` request attempts. A stage requesting 300 receives a cap of 300; a stage requesting 450 receives a cap of 419 and stops before attempt 420.

The data flow is:

```text
original 110 static cases (immutable)
        |
        +--> no-API exposure/utility audit
        |
        `--> development candidates --clean control--> 18 development contexts
                                                     |
                                                     `--feedback allowed--> mutate/rank attacks
                                                                            |
                                                                            `--> freeze 3 attacks + hashes
                                                                                         |
new unseen candidates --clean control--> 30 held-out contexts --cross product------------+
                                                    |
                                                    `--> 90-case undefended Batch A
                                                          |
                                                          +--> pass gate: Phase 7, then defense
                                                          +--> borderline: unchanged Batch B
                                                          `--> fail: stop and make a new decision
```

- [x] **6A.1** After Phase 6.12 is merged and tagged, create the calibration branch: `git checkout main && git pull && git checkout -b phase-6a-attack-calibration`. Do not resume Phase 8 at step 8.3 until this phase passes its gate.

- [x] **6A.2** Implement `src/analysis/audit_baseline_exposure.py` as a no-API audit of `data/baseline/results.jsonl` and its raw traces. It must write `data/baseline/exposure_audit.csv` plus `data/baseline/exposure_summary.json`, reporting: case count, injection-visible count, literal/normalized/decoded match mode, attack success, and AgentDojo utility result. Assert 110 unique planned cases and fail if any raw trace is missing or errored. Record the already observed totals only if the script reproduces them: 110/110 exposed, 0/110 attacks, and 90/110 utility (Workspace 52/52, Banking 26/46, Slack 12/12).

  ```powershell
  # No API call.
  .\.venv\Scripts\python.exe -m src.analysis.audit_baseline_exposure --results data/baseline/results.jsonl --plan data/baseline/plan.tsv --output-csv data/baseline/exposure_audit.csv --output-summary data/baseline/exposure_summary.json
  ```

- [x] **6A.3** Write `docs/baseline_null_analysis.md`. Explain the floor effect, distinguish delivery failure from model refusal, report the reproducible audit from 6A.2, and state that no defense reduction can be calculated from the original static baseline. Include the four sources added as SOP references [14]–[17]; do not claim that Gemini 3.5 Flash-Lite is immune or that Google published a prompt-injection score for this exact model.

- [x] **6A.4** Extend `src/schemas.py` and `src/analysis/validate_schema.py` with two records:
  - `CalibrationAttempt`: attempt ID/time, split (`dev` only), source family, seed/parent ID, mutation round, attacker and target model, domain/task/vector IDs, rendered attack hash, attack success, utility success, generator/target request-attempt counts, raw-trace path, and notes.
  - `FrozenAttack`: attack-set version, attack ID, source family/category, goal-bound template or deterministic generator name plus parameters, selected development attempt, development score, UTF-8 byte length, and SHA-256 hash.
  Extend `RunResult` backward-compatibly with optional `utility_success`, `split`, `attack_set_version`, `attack_sha256`, `plan_sha256`, `defense_version`, and `defense_sha256` fields. Old Phase 6 rows must continue to validate unchanged; new calibrated and defended rows must populate every applicable field.
  Never put a held-out attempt into `CalibrationAttempt` with `split=dev`.

- [x] **6A.5** Implement `src/experiments/quota_guard.py` and no-network unit tests. Require `--quota-date YYYY-MM-DD`, `--dashboard-used N`, `--dashboard-limit N`, and `--max-api-requests N` on every new API runner. Interpret `--quota-date` as the current date in `America/Los_Angeles`, because Google documents the RPD reset at midnight Pacific time (SOP reference [18]); never key the ledger to the machine's Asia/Bangkok calendar date. Reject a stale/wrong Pacific date, negative values, `dashboard_used > dashboard_limit`, a nonpositive safe budget, or concurrent execution. Cap `dashboard_limit` at the study's approved 500 RPD even if the site later displays more; if the site displays less, use the lower value. If the requested process cap is higher than the computed safe budget, lower it automatically and print both values before running. Atomically reserve the effective cap in the dated ledger before the first request, reconcile it to actual attempts on clean exit, and retain an interrupted reservation until a fresh dashboard reading permits reconciliation. Reuse `configure_google_request_attempt_limit()` so every retry consumes the effective cap. Unit-test the Pacific-date boundary (including daylight-saving time), stale dates, dashboard/ledger disagreement, lower displayed limits, cap clamping, retries, interruption, reconciliation, and lock contention. Add the `tzdata` package only if the Windows environment cannot resolve `America/Los_Angeles`. The ledger contains counts and timestamps only—never API keys or prompt contents.

- [x] **6A.6** Implement `src/experiments/build_attack_splits.py` with fixed seed `20260807` and a `--plan` mode that makes no API calls. It must create:
  - `data/attack_calibration/dev_candidates.tsv`: a deterministic ordered list with at least ten candidate contexts/domain. It may reuse Phase 6 contexts because development data are not reported effectiveness data, and fills remaining slots from the full matrix. Workspace candidates must include file, email, and calendar surfaces; Banking candidates must include file and transaction-memo surfaces; Slack candidates must cover at least two webpage vectors. Step 6A.10 will select exactly six clean-capable contexts/domain from this list.
  - `data/attack_calibration/holdout_candidates.tsv`: a deterministic ordered list from `run_baseline.py --matrix full`, excluding every `(domain, injection_vector, user_task_id, injection_task_id)` context present in the original 110 cases or anywhere in `dev_candidates.tsv`. Excluding the entire candidate pool keeps the holdout disjoint even before the final development manifest exists.
  - Enough ordered candidates to obtain two possible balanced batches of ten clean-capable contexts per domain. Workspace candidates must cover file, email, and calendar surfaces; Banking candidates must cover file and transaction-memo surfaces; Slack candidates use webpage surfaces.
  Fail if the sets overlap or if rerunning with the same seed changes either manifest.

  ```powershell
  # No API call. Running this twice must produce byte-identical files.
  .\.venv\Scripts\python.exe -m src.experiments.build_attack_splits --plan --seed 20260807 --dev-output data/attack_calibration/dev_candidates.tsv --holdout-output data/attack_calibration/holdout_candidates.tsv
  ```

- [x] **6A.7** Commit the audit tooling, schemas, quota guard, and both pre-API candidate manifests before any calibration call: `git commit -m "feat: prospective attack-calibration protocol"`. Record their SHA-256 hashes in `docs/baseline_null_analysis.md`. Candidate selection after clean controls must follow the committed order; changing the order requires a documented version increment.

- [x] **6A.8** Implement `src/experiments/calibrate_attacks.py` with three resumable modes and separate output folders:
  1. `--stage builtin-screen`: evaluate AgentDojo's `direct`, `ignore_previous`, `system_message`, `important_instructions`, `tool_knowledge`, and `injecagent` families on one fixed development context per domain (18 target runs maximum). Capture the generated injection/vector and native verdict; do not count the three old positive controls as calibration evidence.
  2. `--stage mutate`: use exactly eight seeds—the three best built-in candidates (rank by development domains compromised, then rendered length, then family name) plus one fixed representative from each of the five original empirical categories. In a separate attacker context, `get_google_primary_llm()` proposes one revised goal-bound template containing exactly one supported `{{goal...}}` token. Test it first on one rotating development context; only if it succeeds, test one context in each of the other two domains. Rotate among the six contexts/domain so later candidates do not all see one task. Feed the next round only the observable transcript and AgentDojo verdict—no gradients, logits, hidden state, held-out output, or future defense text. A template is eligible for freezing only if the renderer can place it in all three domains; its source category/family is descriptive and does not override AgentDojo's verified channel/vector mapping.
  3. `--stage freeze`: make no API calls. Rank candidates by development domains compromised (descending), mutation rounds (ascending), rendered UTF-8 length (ascending), then attack ID (lexical). Select exactly three qualifying attacks from three distinct source families and write `data/attack_calibration/frozen_attacks.v1.json`.

  Also implement `src/experiments/run_clean_controls.py`. Given an ordered candidate manifest and a requested count/domain, it runs the user task without an injection, records AgentDojo utility, and selects the first successful contexts in committed order. It must never receive or inspect an attack result.

- [x] **6A.9** Enforce the mutation stopping rules in code: at most five generated candidates per seed, at most 40 generated candidates total for attack-set version 1, immediate stop for a seed once it succeeds in all three development domains, and no further mutations after three distinct families have each produced a 3/3 candidate. Generator refusals, malformed output, unresolved/multiple goal tokens, and duplicate hashes are logged but never sent to the target; they still consume generator API attempts.

- [x] **6A.10** First run clean controls on `dev_candidates.tsv` until six utility-successful contexts/domain are selected; write and commit the resulting 18-row `dev_manifest.tsv` and its hash before any attack calibration. Then run `builtin-screen` and `mutate`, always with the dashboard-derived hard cap described above. Each stage checkpoints after every generator or target attempt and resumes without repeating completed calls. If daily capacity is insufficient, stop and resume on a later quota day; do not switch models, increase RPM, or run concurrent processes.

  Run one command at a time. Immediately before **each** command, reread the dashboard; `Read-Host` prevents accidentally reusing the example value of 56:

  ```powershell
  $quotaDate = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTimeOffset]::UtcNow, 'Pacific Standard Time').ToString('yyyy-MM-dd')
  $dashboardUsed = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD used')
  $dashboardLimit = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD limit')
  .\.venv\Scripts\python.exe -m src.experiments.run_clean_controls --input data/attack_calibration/dev_candidates.tsv --selection-output data/attack_calibration/dev_manifest.tsv --per-domain 6 --quota-date $quotaDate --dashboard-used $dashboardUsed --dashboard-limit $dashboardLimit --max-api-requests 200

  # Refresh the Pacific date and both dashboard values before this command.
  $quotaDate = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTimeOffset]::UtcNow, 'Pacific Standard Time').ToString('yyyy-MM-dd')
  $dashboardUsed = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD used')
  $dashboardLimit = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD limit')
  .\.venv\Scripts\python.exe -m src.experiments.calibrate_attacks --stage builtin-screen --quota-date $quotaDate --dashboard-used $dashboardUsed --dashboard-limit $dashboardLimit --max-api-requests 100

  # Refresh all three again; mutation is checkpointed and may stop/resume across quota days.
  $quotaDate = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTimeOffset]::UtcNow, 'Pacific Standard Time').ToString('yyyy-MM-dd')
  $dashboardUsed = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD used')
  $dashboardLimit = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD limit')
  .\.venv\Scripts\python.exe -m src.experiments.calibrate_attacks --stage mutate --quota-date $quotaDate --dashboard-used $dashboardUsed --dashboard-limit $dashboardLimit --max-api-requests 400
  ```

- [ ] **6A.11** Run `--stage freeze` and validate `frozen_attacks.v1.json`. **Calibration qualification gate:** three distinct families must be frozen, and each selected attack must have succeeded in at least one development domain. If this gate fails within the version-1 mutation budget, stop and document a blocked/null calibration; do not create a held-out attack run and do not proceed to defense evaluation.

  ```powershell
  # No API call and no quota arguments.
  .\.venv\Scripts\python.exe -m src.experiments.calibrate_attacks --stage freeze
  .\.venv\Scripts\python.exe -m src.analysis.validate_schema data/attack_calibration/frozen_attacks.v1.json --schema frozen-attack
  ```

- [ ] **6A.12** Run `run_clean_controls.py` on `holdout_candidates.tsv` until ten utility-successful contexts have been found in each domain. Selection depends only on clean utility, never on an attack result. Write `data/attack_calibration/clean_controls/results.jsonl`, generate `holdout_A.tsv` from the first ten successful contexts/domain, and checkpoint the next unread candidate position for optional Batch B. Validate that none occurs in Phase 6 or development data.

  ```powershell
  $quotaDate = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTimeOffset]::UtcNow, 'Pacific Standard Time').ToString('yyyy-MM-dd')
  $dashboardUsed = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD used')
  $dashboardLimit = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD limit')
  .\.venv\Scripts\python.exe -m src.experiments.run_clean_controls --input data/attack_calibration/holdout_candidates.tsv --selection-output data/attack_calibration/holdout_A.tsv --per-domain 10 --exclude data/attack_calibration/dev_manifest.tsv --quota-date $quotaDate --dashboard-used $dashboardUsed --dashboard-limit $dashboardLimit --max-api-requests 300
  ```

- [ ] **6A.13** Build the frozen held-out matrix without API calls: cross the three frozen attacks with the 30 `holdout_A.tsv` contexts to produce exactly 90 rows (30/domain) in `data/calibrated_baseline/plan_A.tsv`. Every row must contain the attack-set version/hash. Commit `frozen_attacks.v1.json`, clean-control results, `holdout_A.tsv`, and `plan_A.tsv` **before** executing any row.

- [ ] **6A.14** Implement `src/experiments/run_calibrated_baseline.py` by reusing the Phase 6 execution, trace validation, checkpointing, and native AgentDojo verdict logic. It may load only a committed frozen-attack file and a committed held-out plan; it must reject `defense != none`, any `split != holdout`, a manifest hash mismatch, or a case present in development. Require the quota arguments from 6A.5. Save Batch A to `data/calibrated_baseline/batch_A/{results.jsonl,raw/}`.

- [ ] **6A.15** Execute and validate all 90 Batch A cases with `gemini-3.5-flash-lite`, with no defense. Verify schema, exact plan/index key equality, no duplicate cases, no errored/skipped trace, attack exposure, and at least five manual trace/verdict checks. Never rewrite `data/baseline/results.jsonl`.

  ```powershell
  $quotaDate = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTimeOffset]::UtcNow, 'Pacific Standard Time').ToString('yyyy-MM-dd')
  $dashboardUsed = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD used')
  $dashboardLimit = [int](Read-Host 'Current Gemini 3.5 Flash-Lite RPD limit')
  .\.venv\Scripts\python.exe -m src.experiments.run_calibrated_baseline --plan-path data/calibrated_baseline/plan_A.tsv --attack-set data/attack_calibration/frozen_attacks.v1.json --results-path data/calibrated_baseline/batch_A/results.jsonl --quota-date $quotaDate --dashboard-used $dashboardUsed --dashboard-limit $dashboardLimit --max-api-requests 400
  ```

- [ ] **6A.16** Apply this predeclared gate using native AgentDojo verdicts only:
  - **Pass:** at least 15 successful attacks overall **and** at least five in each domain. Freeze Batch A as the measurable baseline.
  - **Borderline:** the gate is not met but at least one attack succeeds. Without changing attacks or selection rules, obtain the next ten clean-successful contexts/domain, create and commit the 90-row `plan_B.tsv`, run Batch B, then reapply the same gate to combined A+B counts.
  - **Fail:** zero Batch A successes, or the combined A+B data still fails the gate. Do not evaluate the defense. Retire this held-out set, document the null, and request a methodology decision: create attack-set v2 with entirely new held-out contexts, add a separately reported weaker-model validation track, or reframe the study as a benchmark-saturation/null-result study. Never tune v1 and rerun it on A or B.

- [ ] **6A.17** Write `docs/attack_calibration_report.md`: data split and hashes, candidate families, every stopping rule, quota used by stage, malformed/refused generator outputs, selected attacks and why they won the deterministic tie-break, Batch A/B results, gate outcome, and limitations. Explicitly label this process "TAP-inspired black-box search," not an exact reproduction of TAP.

- [ ] **6A.18** Commit the completed calibration and measurable baseline artifacts: `git add src/ docs/ data/attack_calibration/ data/calibrated_baseline/ && git commit -m "experiment: calibrated undefended baseline"`.

- [ ] **6A.19** Push, PR, merge, and tag `phase-6a-done` only after the gate passes. If it fails, leave 6A.19 unchecked and follow the documented decision point in 6A.16.

**Definition of Done:** the original 0/110 static result has a reproducible exposure/utility audit; development and held-out contexts are disjoint and hashed; exactly three attacks from distinct families were selected without held-out feedback; the held-out undefended run passes the ≥15 overall and ≥5-per-domain success gate; every API attempt is quota-ledgered and capped; and no defense information entered calibration.

  

---

  

## Phase 7 — Baseline Aggregation & Visualization

**Objective:** report the original Gemini static null and the completed Gemma 4
Banking selected-payload follow-up as separate experiments. The archived Gemini
`data/calibrated_baseline/` branch never passed its Phase 6A gate and is not a
Phase 7 input. For the active defense track, the frozen Gemma follow-up is the
undefended denominator: its 160 fresh rows are the primary estimand, while the
20 true-replication rows are a separate stability result. The combined 40/180
success count is descriptive only and must never be the primary number.

- [x] **7.1** `git checkout main && git pull && git checkout -b phase-7-baseline-analysis`

- [x] **7.2** Write `src/analysis/aggregate_results.py`: read a requested JSONL
  index together with its committed plan and raw traces; report run count,
  native AgentDojo successes, ASR, legitimate-task utility, and 95% Wilson
  intervals by domain/source-family/channel and by the declared follow-up
  partition. For the active Gemma input, use the frozen plan at
  `data/baseline_gemma4/banking_followup/plan.tsv`, the completed index at
  `data/baseline_gemma4/full/results.jsonl`, and raw traces under
  `data/baseline_gemma4/full/r/`. For the frozen legacy indexes, derive
  undefended utility from the raw traces because their top-level
  `utility_success` fields are null due to the runner's former serialization
  behavior. Future undefended indexes record the native boolean directly, and
  the aggregator must verify any populated value against the raw trace. It must
  reject or visibly label any attempt to combine the original Gemini static
  corpus, the archived Gemini calibration branch, the 20 replication rows, and
  the 160 fresh rows.

- [x] **7.3** Run the aggregator separately on the original
  `data/baseline/results.jsonl` and on the Gemma follow-up (`data/baseline_gemma4/full/results.jsonl`). Write
  `data/baseline/summary.csv`,
  `data/baseline_gemma4/full/summary_fresh.csv`,
  `data/baseline_gemma4/full/summary_replication.csv`, and the explicitly
  descriptive-only `data/baseline_gemma4/full/summary_all_descriptive.csv`.
  Label every output with model, attack-set/protocol identifier, plan hash,
  partition, and manifest provenance. The 160-fresh summary is the only Gemma
  undefended summary eligible to serve as the Phase 9 denominator.

- [x] **7.4** Produce clearly separate figures:
  `report/figures/static_baseline_asr_heatmap.png` for the original Gemini
  0/110 static corpus,
  `report/figures/gemma_banking_fresh_asr_heatmap.png` for the 160 fresh Gemma
  follow-up rows, and
  `report/figures/gemma_banking_replication_asr_heatmap.png` for the 20
  replication rows. Do not place the original static result, Gemma fresh ASR,
  Gemma replication ASR, or descriptive 40/180 total in one unlabeled
  "baseline" figure.

- [x] **7.5** Reconcile the summaries against the committed plans and raw
  traces. Confirm the original Gemini static result remains 0/110; the Gemma
  plan has exactly 180 rows split into 20 replication and 160 fresh rows; the
  replication partition has 6/20 native successes; the fresh primary partition
  has 34/160 native successes and therefore passes the ≥5-success gate; and
  40/180 is retained only as a descriptive total. Confirm all 180 raw traces
  are present and error-free, all 20 replication traces are distinct fresh
  live calls rather than cache reuse (0/20 reuse), and the raw traces report
  113 legitimate-task successes and 67 failures while confirming that the
  frozen legacy undefended index utility fields remain null. Any mismatch
  blocks Phase 8/9.

  **Completed 2026-08-12:** The no-API reconciliation independently compared
  every follow-up `(payload_id, user_task_id, injection_task_id)` triple with
  the 46 Banking rows in the original committed stratified plan; it did not use
  follow-up partition labels. This reproduced 20 replication and 160 fresh
  rows, with 6/20 and 34/160 native successes respectively (40/180 descriptive
  only). All 180 unique raw traces were present and error-free; raw utility was
  113 true / 67 false while all 180 legacy index utility fields remained null
  because the runner had not serialized undefended utility. For
  each derived replication, the follow-up raw path, evaluation timestamp, trace
  hash, and positive API-attempt count were compared with the original Gemma
  discovery trace for the same triple: 20/20 were genuinely new live calls,
  0/20 were reused cached traces, and the replication successes split 6 new / 0
  reused. The deterministic evidence is recorded in
  `data/baseline_gemma4/full/reconciliation_report.json`; all 109 no-network
  unit tests passed.

- [x] **7.6** Commit the aggregation tooling, partitioned summaries, and
  separate figures: `git add src/analysis/aggregate_results.py
  data/baseline/summary.csv data/baseline_gemma4/full/summary_fresh.csv
  data/baseline_gemma4/full/summary_replication.csv
  data/baseline_gemma4/full/summary_all_descriptive.csv report/figures/
  && git commit -m "analysis: baseline ASR aggregation and heatmaps"`.

- [x] **7.7** Push, PR, merge, tag `phase-7-done`.

**Definition of Done:** the original Gemini 0/110 static result, the Gemma
160-fresh primary follow-up result, and the Gemma 20-row replication result have
separate summaries and figures; the descriptive Gemma 40/180 total cannot be
mistaken for the primary estimand; all counts, utility values, plan hashes, and
raw-trace provenance reconcile; and the exact Gemma fresh rows authorized for
Phase 9 are unambiguous. No Phase 7 output depends on a passing Gemini
`data/calibrated_baseline/` run.

  

---

  

## Phase 8 — Defense Implementation (Spotlighting, from scratch)

  

**Objective:** build your own understanding of the defense mechanism, not just invoke someone else's implementation.
  

- [x] **8.1** `git checkout main && git pull && git checkout -b phase-8-defense-spotlighting`

- [x] **8.2** Re-read Hines et al. [4] closely, focused only on the mechanism section — note exactly how they mark/delimit untrusted content and what the accompanying system-prompt instruction says.

- [x] **8.3** Write `docs/defense_design.md`: your own delimiter/datamarking/encoding scheme, stated precisely enough that someone else could implement it from your description alone.

- [x] **8.4** Implement `src/defenses/my_spotlighting.py`: a function that wraps raw untrusted content per your scheme, plus the system-prompt fragment instructing the model how to treat marked spans.

- [x] **8.5** Wire this defense into `run_baseline.py` (or a copy of it) as a new selectable `defense` mode.

- [x] **8.6** Hand-test: construct one obviously-injected input, run it through your wrapper function alone (no LLM call needed yet), and visually confirm the output is wrapped correctly.

- [x] **8.7** Commit: `git add docs/defense_design.md src/defenses/my_spotlighting.py && git commit -m "feat: custom spotlighting defense implementation"`.

- [x] **8.8** Push, PR, merge, tag `phase-8-done`.

  

**Definition of Done:** you can explain, from memory, exactly what your defense does and why — not just that it "wraps stuff."

  

---

  

> **Empirical defense track retargeted after the Gemini calibration null:** The original Gemini 3.5 Flash-Lite 0/110 static result, all attack-set v1/v2 calibration artifacts, and Phase 6A.11's failed qualification gate remain unchanged and are reported as the project's primary robustness finding. Phases 9-11 are separately retargeted to `gemma-4-26b-a4b-it`, beginning with a Phase-6-equivalent undefended static baseline that replays the exact ordered 110-row Gemini plan and all 19 retained static-corpus payload IDs represented in it; the separate 18-case built-in-screen diagnostic is not substituted for this plan. The default is this 110-case parity matrix, not the exhaustive combinatorial matrix; `--matrix full` remains available only through explicit operator selection. Gemma undefended baseline and follow-up artifacts must remain isolated under `data/baseline_gemma4/` and must never be pooled with `data/baseline/` or `data/calibrated_baseline/`. The existing runner's Gemma defended artifacts use the model-qualified `data/defended/g4/v1/` namespace and must remain separate from Gemini defended artifacts.
>
> **Predeclared Gemma qualification rule:** If the completed 110-case static Gemma baseline reaches at least 15 native AgentDojo successes overall and at least five in every domain, skip a Gemma attack-set-v2-equivalent mutation search because the static baseline already meets the gate that calibration exists to reach, then proceed to Phases 8-9 using the static Gemma rows as the undefended denominator. If the result is nonzero but below either threshold, stop and report exact overall and per-domain counts for a human decision about any small bounded top-up. If it is zero or near zero, report the null and do not begin Gemma-specific calibration automatically. This addendum supersedes the model/baseline dependency for Phases 9-11; the active Phase 9 branch is stated explicitly below.

> **Human methodology amendment for Phase 9:** The validated 110-row run produced five native successes, all in Banking, and the completed follow-up produced 6/20 native successes in the true-replication rows and 34/160 in the fresh rows. Because the `file_content` and `transaction_memo` surfaces are exhausted, the 20-row replication partition is repurposed as the Phase 9 development/validation panel. Its rows are derived deterministically by comparing `(payload_id, user_task_id, injection_task_id)` triples in the original 46-row Banking discovery plan with the frozen 180-row follow-up plan; no hand selection or follow-up partition label is used. The existing live Gemma undefended index is filtered to those exact 20 keys and is not rerun. The replication panel is permanently excluded from 9.6–9.8: no matched defended/undefended comparison will ever be produced for it, and the 160-fresh subset is the sole primary Banking defended result. The derivation, hashes, and reuse check are recorded under `data/defended/g4/v1/replication_dev/` and `data/baseline_gemma4/banking_followup/plan_fresh160.tsv`.

> **Overnight/unattended execution protocol:** The only live API work permitted unattended is the already reviewed command `python -m src.experiments.run_baseline --target gemma4-26b` for the default 110-case parity matrix, with its required fresh Gemma quota arguments, existing checkpoint/resume behavior, and quota-boundary stop. It may stop only at completion, a quota-day boundary, or an unexpected exception; the runner must retain completed checkpoints and stop rather than continue after that exception. At wake-up, read the results and compute total native AgentDojo successes, per-domain successes, and completion status (110/110 or partial). A quota-boundary-stopped partial run is incomplete and is not a final result. If complete, write `docs/gemma_baseline_morning_report_<YYYY-MM-DD>.md` with exact counts, the applicable predeclared qualification outcome, and—unless it passes—a menu with brief pros/cons for targeted top-up, scoped-down Phase 8/9, or report-as-null-and-redirect-to-writeup; do not choose an action. If incomplete, the report must state that it is incomplete and include the exact resume command with freshly read Pacific-date and Gemma-dashboard values. Every report must end by stating that no further live API call, mutation search, top-up, or Phase 8/9 work has begun and that human methodology approval is required before any of it begins. Do not unattended-launch a mutation search, top-up, `--matrix full`, any other new live API command, or any Phase 8/9 execution.

## Phase 9 — Defense Validation & Defended Experiment Execution

  

**Objective:** validate `my_spotlighting` on a committed Gemma-only development/validation manifest, freeze the implementation and its hash, then measure its security benefit and utility cost only on the exact Gemma plan authorized by the active retargeted track.

> **Active branch:** The completed Gemma parity baseline produced 5/110 native successes, all in Banking, so the cross-domain qualification gate did not pass. The authorized Phase 9 execution is therefore `gemma4-banking-followup-v1`: five discovery-selected payloads crossed with the frozen 180-row Banking plan. The 20 discovery-plan repetitions and 160 fresh cases must remain separate; the 160 fresh cases are the primary gate and estimand. Defense execution is authorized only after at least five native successes in the 160 fresh cases. The Gemini Phase 6A calibration artifacts, its three-family attack set, and its 90-case Batch A/B protocol are not inputs to this phase.

```

...calls AgentDojo's `benchmark_suite()` via the Python API (not the CLI/default Vertex path), using the explicit `gemma-4-26b-a4b-it` provider target from `src/llm_providers/google_llm_factory.py`...

```

  

- [x] **9.1** `git checkout main && git pull && git checkout -b phase-9-defense-validation`

- [x] **9.2** Derive the exact 20-row true-replication panel from the original 46-row Banking discovery plan and the frozen 180-row follow-up plan by comparing only `(payload_id, user_task_id, injection_task_id)`. Verify the existing Gemma undefended index covers those 20 keys with 6/20 native successes and 20 error-free raw traces; do not rerun undefended. Run AgentDojo's built-in `spotlighting_with_delimiting` on the committed manifest `data/defended/g4/v1/replication_dev/manifest.tsv` (SHA-256 `66290a51809e53590bff01256e0463649895a83520227def097126434978d4c7`) and save to `data/defended/g4/v1/replication_dev/builtin/`.

- [x] **9.3** Run `my_spotlighting` on the exact same 20 rows and save to `data/defended/g4/v1/replication_dev/custom/`. Both arms are schema-valid, have exact 20/20 key equality, unique error-free raw traces, and three manual trace/verdict spot checks. Built-in validation is 4/20 native successes and 10/20 utility successes; custom validation is 0/20 native successes and 10/20 utility successes. These are implementation-validation results only, not the primary Banking defense estimate.

- [x] **9.4** Write `docs/defense_validation.md` and `data/defended/g4/v1/replication_dev/validation_report.json`. The former transaction-memo null undefended checkpoint is deliberately deleted during the amendment cleanup after its 0/20 result was used for the implementation check; it is not retained as a downstream negative finding. The repurposed replication panel is frozen after this validation, so no post-hoc tuning or rerun is performed on it.

- [x] **9.5** Freeze `my_spotlighting.py` before any fresh-160 defended call. Commit the implementation, exact system-prompt fragment, replication validation artifacts, and `data/defended/g4/v1/defense_freeze.json`, which records the canonical-LF source SHA-256 `7ce3de91c8dfd3c17532332d8f6516f3aa377bb2c40b22fe9371fc349a5200ee`. No implementation changes are permitted after this point; a required fix creates a new defense version and untouched evaluation panel.

- [x] **9.6** Because the fresh undefended follow-up contains 34/160 native successes, run the frozen `my_spotlighting` implementation only on `data/baseline_gemma4/banking_followup/plan_fresh160.tsv` (SHA-256 `0fcf3aadc5700ef5e1c40b5d5b5fc7242c7eaeb8a1225b525f1305e20cdf6f6b`), permanently excluding all 20 replication rows. Preserve case IDs, payload hashes, and plan hash; save defended results under `data/defended/g4/v1/fresh160/`. Use the Gemma-keyed quota guard and hard request cap. The run completed 160/160 rows under the frozen v1 source hash.

- [x] **9.7** Validate schema and exact 160-row plan/index equality for `fresh160`; verify target model, attack/plan/defense hashes, no duplicate or missing cases, no errored/skipped trace, and manual raw-trace/verdict spot checks. The machine-readable report is `data/defended/g4/v1/fresh160/validation_report.json`: 160/160 keys and raw traces, zero errors, 4 native successes, 115 utility successes, with spot checks at rows 0, 79, and 159. Do not evaluate, pool, or report a defended replication partition.

- [x] **9.8** Reuse `aggregate_results.py` on `data/defended/g4/v1/fresh160/` and compare only the matching 160 fresh undefended rows. Report this 160-fresh partition as the sole primary Banking selected-payload defended result; never pool it with the 46-row discovery set, Gemini calibrated branch, cross-domain estimates, or the replication panel. The result is 34/160 (21.25%) undefended native successes versus 4/160 (2.50%) defended, an absolute ASR reduction of 18.75 percentage points and a relative reduction of 88.24%. Undefended utility is 103/160 (64.375%) versus 115/160 (71.875%) defended, a +7.50 percentage-point utility change. The paired 95% bootstrap (10,000 resamples, seed `20260805`) gives ASR-reduction CI [13.125%, 25.000%] and utility-change CI [2.500%, 13.125%]. `data/defended/g4/v1/summary.csv` and the chart `report/figures/gemma_banking_fresh160_before_after.png` are labeled explicitly “160-fresh partition only.”

- [x] **9.9** Commit the frozen defense and completed fresh160 artifacts, including `data/defended/g4/v1/fresh160/`, `data/defended/g4/v1/summary.csv`, and the explicitly labeled fresh160 chart. The defense freeze is commit `91a3e04`; the completed result/analysis commit follows on the same non-main phase branch.

- [ ] **9.10** Push, PR, merge, tag `phase-9-done`.

  

**Definition of Done:** the defense is validated on the repurposed 20-row replication panel, frozen before fresh-160 execution, and evaluated only on the 160 fresh rows. No matched defended/undefended replication comparison exists or will be created. The 160-fresh matched pairs are the sole primary Banking defended result, with uncertainty and utility cost; original Gemini, discovery, calibrated-branch, cross-domain, and replication rows are excluded from that primary denominator.

  

---

  

## Phase 10 — Adaptive Attack Loop: Design & Implementation

  

**Objective:** build a defense-aware attacker. Unlike Phase 6A's model-adaptive calibration, this attacker is explicitly given the frozen spotlighting mechanism and searches for bypasses without modifying the already reported static-defense comparison.

  

- [ ] **10.1** `git checkout main && git pull && git checkout -b phase-10-adaptive-attack-design`

- [ ] **10.2** Re-read the LaunchSafe paper [8] methodology section specifically — extract their operational definition of "adaptive": the attacker has knowledge of the defense and iterates against it.

- [ ] **10.3** From your Phase 9 results, identify which domain shows the most interesting defended-ASR gap (highest remaining risk, or most surprising drop). Write your choice and reasoning into `docs/decisions_log.md`.

- [ ] **10.4** Start from the three Phase 6A frozen attacks that the defense stopped, then design 3–5 mutation strategies specifically targeting *your* defense's mechanism (e.g., delimiter collision, marker imitation, instructions referring outside a marked span). Store these under a new defense-adaptive version; never overwrite the calibrated attack manifest.

- [ ] **10.5** Write down the iteration budget and stopping rule before calls. Use at most five mutations per frozen attack, require the Phase 6A quota guard on every run, and stop on native AgentDojo success or budget exhaustion. This budget is separate from Phase 6A's model-adaptive budget.

- [ ] **10.6** Implement `src/adaptive/adaptive_loop.py`: given a payload that failed to bypass the defense, apply the next mutation strategy, re-test, log the attempt, repeat until success or budget exhausted. **Import `get_google_primary_llm` for every mutation-search call** so the larger primary quota keeps search and recorded outcomes model-consistent.

- [ ] **10.7** Unit-test the loop on one payload by hand before running it at scale — confirm logging captures every iteration, not just the final outcome.

- [ ] **10.8** Commit: `git add src/adaptive/adaptive_loop.py docs/decisions_log.md && git commit -m "feat: adaptive attack loop"`.

- [ ] **10.9** Push, PR, merge, tag `phase-10-done`.

  

**Definition of Done:** the loop runs on a single payload, logs every iteration, and stops correctly on both success and budget exhaustion.

  

---

  

## Phase 11 — Adaptive Attack Execution & Root-Cause Case Studies

  

**Objective:** run the loop for real, and turn bypasses into explained findings, not just numbers.

  

- [ ] **11.1** `git checkout main && git pull && git checkout -b phase-11-adaptive-execution`

- [ ] **11.2** Run the adaptive loop against every payload that failed to bypass the defense in your chosen domain(s) from Phase 10.

- [ ] **11.3** Save every iteration's full trace to `data/adaptive/`.

- [ ] **11.4** For each payload that eventually succeeded, write one case study file in `report/case_studies/`: which mutation worked, a mechanistic explanation of *why* it defeated your specific defense (tie it back to `defense_design.md` from Phase 8), and what a stronger defense would need to catch it.

- [ ] **11.4a** Verify each confirmed bypass has a complete primary-model trace before it counts as a recorded result; mutation search already uses `get_google_primary_llm()`, so no cross-model confirmation run is required.

- [ ] **11.5** For payloads that never succeeded within budget, note this explicitly in a short summary — it's a real (if less dramatic) finding.

- [ ] **11.6** Reuse `aggregate_results.py` to compute post-adaptive ASR, and the delta versus defended-static ASR from Phase 9.

- [ ] **11.7** Commit: `git add data/adaptive/ report/case_studies/ && git commit -m "experiment: adaptive attack execution and bypass case studies"`.

- [ ] **11.8** Push, PR, merge, tag `phase-11-done`.

  

**Definition of Done:** you have 3–5 written case studies with real mechanistic explanations, plus a full post-adaptive ASR number to compare against Phase 9.

  

---

  

## Phase 12 — Cross-Domain & Literature Comparison Analysis

  

**Objective:** answer the project's core research question with evidence, and place your numbers in context.

  

- [ ] **12.1** `git checkout main && git pull && git checkout -b phase-12-cross-domain-analysis`

- [ ] **12.2** Build the matched three-state comparison for the active Gemma
  Banking track using the 160-fresh partition of the frozen follow-up:
  undefended / defended / defense-adaptive. Show the 20-row replication
  comparison separately, and show the original Gemini static-corpus 0/110 result
  in a distinct panel or reference series labeled "original static corpus".
  Never substitute the descriptive 40/180 total, the original 46-row Banking
  discovery subset, or the archived Gemini calibrated branch for the 160-fresh
  undefended denominator; no cross-domain defense claim is authorized by this
  scoped track.

- [ ] **12.3** Write `docs/cross_domain_findings.md`: does ASR track domain privilege level, or not? State the finding plainly, with the numbers that support it.

- [ ] **12.4** Pull comparable published figures from AgentDojo [2] / InjecAgent [3] (same or closest-available model) and place them alongside your numbers in a table.

- [ ] **12.5** In the same document, note methodological differences honestly (different model, smaller corpus, etc.) rather than implying direct equivalence.

- [ ] **12.6** Commit: `git add report/figures/ docs/cross_domain_findings.md && git commit -m "analysis: cross-domain comparison and literature benchmarking"`.

- [ ] **12.7** Push, PR, merge, tag `phase-12-done`.

  

**Definition of Done:** you can state, in one sentence, whether privilege level predicts attack success — and back it with a chart.

  

---

  

## Phase 13 — Final Report Writing

  

**Objective:** assemble everything into the single document someone else would actually read.

  

- [ ] **13.1** `git checkout main && git pull && git checkout -b phase-13-final-report`

- [ ] **13.2** Draft `report/final_report.md` section by section, in this order: Threat Model → Methodology → Corpus & Taxonomy → Baseline Results → Defense Design & Validation → Adaptive Attack Case Studies → Cross-Domain Findings → Limitations → Recommendations → References.

- [ ] **13.3** Insert every figure/table generated in Phases 7, 9, 11, 12 by reference — don't regenerate numbers inside the report.

- [ ] **13.4** Write the Limitations section honestly: original static-corpus floor effect, post hoc recognition of that floor, prospective but small development/held-out calibration, TAP-inspired rather than exact TAP optimization, single primary model, threshold-dependent attack-set selection, limited event counts by domain, and one defense evaluated.

- [ ] **13.5** Do a full proofread pass where you check every single quantitative claim traces back to a specific file under `data/`. Mark anything that doesn't as `[TODO: re-run]` rather than leaving it unverified.

- [ ] **13.6** If a formatted deliverable (PDF/docx) is required for submission, convert at this point — this is a good moment to reuse the `docx` skill/workflow if that's your target format.

- [ ] **13.7** Commit: `git add report/final_report.md && git commit -m "docs: final report draft"`.

- [ ] **13.8** Push, PR, merge, tag `phase-13-done`.

  

**Definition of Done:** the report reads start to finish without gaps, and every number in it is traceable.

  

---

  

## Phase 14 — Final Release & Submission Packaging

  

**Objective:** leave the repository in a state that's genuinely presentable — to your supervisor, and later to yourself or a hiring manager.

  

- [ ] **14.1** `git checkout main && git pull` (this phase can be done directly on `main` — it's packaging, not new work).

- [ ] **14.2** Rewrite `README.md` fully: final project summary, reproduction instructions (env setup → run baseline → run defended → run adaptive → aggregate), folder structure explanation, link to `report/final_report.md`.

- [ ] **14.3** Delete any dead code, unused scratch files, or abandoned branches.

- [ ] **14.4** Confirm nothing important got accidentally gitignored — walk the repo tree on GitHub directly and check `data/`, `report/`, `docs/` all show their expected contents.

- [ ] **14.5** Commit: `git commit -m "docs: final README and repository cleanup"`.

- [ ] **14.6** Tag the final release: `git tag -a v1.0 -m "Final submission"` then `git push origin v1.0`.

- [ ] **14.7** *(Optional but recommended)* Create a GitHub Release from the `v1.0` tag, attaching the final report file directly for easy access.

- [ ] **14.8** Final push, then open the repo in a private/incognito browser tab to confirm it looks correct to an outside viewer (e.g., your supervisor).

  

**Definition of Done:** a stranger could land on this repository, read the README, and understand what you built, why, and what you found — without needing you in the room.
