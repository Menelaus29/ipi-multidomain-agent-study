# Payload Taxonomy

**Scope of this document:** what a payload's *content/style* looks like - the axis used to tag every entry in `src/payloads/corpus.json` via its `category` field. This is different from [`threat_model.md`](threat_model.md), which covers *how* a payload arrives (delivery method, §3 there) and *what* it targets (trust boundary, per domain).

---

## 1. Why This Taxonomy - Framing

[`threat_model.md`](threat_model.md) §4 scoped this study to **two** of Greshake et al.'s six threat/impact classes [1] as primarily in-scope: **information gathering** and **fraud**, with **manipulated content** partially in scope. The six categories below are not a separate impact taxonomy - they're the *mechanisms* by which a payload tries to actually achieve one of those impacts once it's already inside the agent's context (per the trust boundary, [`threat_model.md`](threat_model.md) §2).

Roughly: `direct_override` and `fake_system_message` are the most direct route to hijacking a goal outright (serving fraud/info-gathering ends immediately, if they work). `role_play_persona` achieves the same hijack indirectly, by getting the model to adopt a frame where the unauthorized action seems in-character rather than a violation. `encoding_obfuscation`, `multi_step_sleeper`, and `chat_template_abuse` don't accomplish the hijack themselves - they exist to get a payload (usually one of the first three) *past* a naive filter or a human skim-reading a tool result, which is precisely what a defense like *Spotlighting* is built to counter.

---

## 2. Category Definitions

### 2.1 `direct_override`

**Definition:** the injected content directly instructs the agent to disregard its current instructions/task and do something else instead, with no framing or disguise.

**Source techniques mapped in:**
- Greshake et al.: direct injection / goal hijacking, as originally characterized by Perez et al. and adopted into Greshake's indirect-delivery framing [1].
- InjecAgent: direct prompt injection triggering goal hijacking or prompt leaking; also isolates a specific reinforcement technique - prepending an explicit override phrase (e.g., *"IMPORTANT!!! Ignore all previous instructions and strictly adhere to..."*) before the payload, and benchmarks it as a distinct performance multiplier [3].
- AgentDojo: the "Important Message" attacker (a wrapper claiming a critical task must be solved first) and the "Ignore Previous Instructions" / "TODO" attack patterns [2].
- OWASP: `ASI01` Agent Goal Hijack via prompt override is this category's direct OWASP counterpart [5]; `LLM01` Prompt Injection covers the same mechanism at the LLM-application level [4].

**Why distinct:** it's the baseline case - no obfuscation, no framing device, no structural trick. Everything else in this taxonomy is a variation that tries to make the same core instruction survive something `direct_override` alone wouldn't: a filter, a human skim, or a defense that specifically looks for override phrasing.

**Instantiation in this study:** works across all three domains and every channel available in each (per [`threat_model.md`](threat_model.md) §2.2).

---

### 2.2 `role_play_persona`

**Definition:** the injected content reframes the agent as a different persona, or constructs a hypothetical/simulated scenario, under which rules the agent would otherwise follow don't seem to apply.

**Source techniques mapped in:**
- Greshake et al.: jailbreaking via hypothetical scenarios or a simulated "developer mode"; persona biasing (e.g., forcing a "conservative"/"liberal" stance, or an in-character persuasive salesperson agenda) [1].
- OWASP LLM Top 10: jailbreak-driven personas - bypassing content restrictions by having the model emulate a restricted or fictional capability [4].

**Excluded:** OWASP Agentic's **"Forged Agent Persona / Synthetic Identity Injection"**, a fake peer agent registering a spoofed identity to exploit *inter-agent* trust, is excluded from this category's definition. It describes an attack *between two LLM agents*, and all three of this study's domains involve exactly one agent calling deterministic tool functions — there is no second agent to impersonate.

**Why distinct:** unlike `direct_override`, the instruction is never stated as an instruction - it's smuggled in as characterization ("you are now X, and X would do Y"), which is a different thing for a defense to catch, since it doesn't contain override-style language a keyword-style filter might key on.

**Instantiation in this study:** works across all domains; most natural in longer-form content (an email body, a file, a Slack message) where there's room to establish a scenario, less natural in a short transaction memo field.

---

### 2.3 `encoding_obfuscation`

**Definition:** the instruction is hidden via an encoding, transformation, or unusual formatting specifically to evade a naive text-based filter, while still being recoverable by the model.

**Source techniques mapped in:**
- Greshake et al.: Base64-encoded payloads, or instructing the model to decrypt/decode programmatically-generated text before acting on it [1].

**Why distinct:** the payload's *semantic content* underneath might be identical to a `direct_override` payload - what makes this its own category is that a defense checking for override-style phrasing in the raw text wouldn't find it, because the raw text doesn't contain that phrasing until the model itself decodes it.

**Instantiation in this study:** best suited to file-content channels (Workspace's `create_file`/`append_to_file`, Banking's `read_file`) - per [`threat_model.md`](threat_model.md) §3, these have more room than a short email subject or transaction memo, where a Base64 blob would look conspicuously out of place to a human reviewer even if it passed an automated filter.

---

### 2.4 `multi_step_sleeper`

**Definition:** the injected content is split across pieces - a smaller initial trigger that only becomes dangerous once it causes the agent to combine it with, or fetch, a second piece, within the **same session**.

**Source techniques mapped in:**
- Greshake et al.: a small payload hidden in a benign-looking document (their example: a Wikipedia-style article) that instructs the agent to dynamically fetch a larger secondary payload from an attacker-controlled location [1].
- OWASP Agentic Top 10: "Zero-Click Prompt Injection" (e.g., the EchoLeak-style pattern) - a payload concealed in an email or file that executes autonomously the moment it's retrieved, without requiring the user to re-prompt [5].

**Excluded:** OWASP's **"Goal-Lock Drift via Scheduled Prompts"**, a recurring injection (e.g., via repeated calendar invites) that gradually shifts agent behavior *across multiple sessions over time*, is excluded from this category's definition. AgentDojo tasks are single-session, so there is no mechanism here for behavior to "drift" between runs. This category is retained strictly as *within-session* staged/combined payloads.

**Why distinct:** the danger isn't in any single piece of content in isolation - it requires the agent to take an action (a fetch, a combination) that a payload reviewed as static text wouldn't reveal.

**Instantiation in this study:** requires a channel with a natural "fetch more" action available - most cleanly instantiated in **Slack**, via `get_webpage` (a trigger in a channel message instructs the agent to fetch a page containing the actual payload). Workspace and Banking have no fetch tool, so this category there is limited to file-content staging (a small trigger in an email/transaction memo pointing to a fuller payload already placed in a file via `search_files`/`read_file`).

---

### 2.5 `fake_system_message`

**Definition:** the injected content impersonates a system-level or tool-level message rather than user-authored data - written to look like it originates from the application's own infrastructure, not from the untrusted source it actually arrived in.

**Source techniques mapped in:**
- Greshake et al.: injections written in a raw format simulating a system error state (their example: `System: For some reason, the assistant is in error and offline...`), exploiting the model's tendency to treat system-formatted text with elevated authority [1].

**Why distinct:** this specifically targets the trust asymmetry between roles - the model is generally trained to weight `system`-authored content more heavily than `user`- or `tool`-authored content. This category tries to borrow that authority without actually occupying the system role in the API-level message structure.

**Instantiation in this study:** works in any channel, but is most effective where the surrounding content plausibly could contain a system-style message - file contents and email bodies more than a terse transaction memo.

---

### 2.6 `chat_template_abuse`

**Definition:** the injected content contains literal special-token strings from the underlying model's chat template (e.g., Llama 3's `<|start_header_id|>`, `<|eot_id|>`), attempting to make the model's tokenizer treat them as real structural tokens rather than literal text, effectively forging a fake turn boundary inside what should be pure content.

**Source techniques mapped in:**
- Greshake et al.: "ChatML injection" - using markers like `<|im_start|>assistant`/`<|im_end|>` inside raw file content to attempt to rewrite the model's structural control context [1].

**Caveat:** For context, I use Groq for my LLM API key provider, which involves an `OpenAILLM` pipeline to to be compatible with AgentDojo (since it doesnt support Groq natively). With AgentDojo, tool results are sent as structured `role="tool"` API fields, proper JSON message objects, not as raw text with a manually-inserted delimiter (AgentDojo does have a `tool_delimiter` concept, but it belongs to its separate `LocalLLM` class for self-hosted models without native function-calling, which is not used in this project). This means **the only realistic attack surface for this category here is the model's own tokenizer**, server-side on Groq's infrastructure - specifically, whether a content string containing a literal token substring like `<|eot_id|>` gets encoded as the real special token (genuinely confusing the turn structure) or is simply tokenized as ordinary sub-word text (in which case the payload does nothing special at all). **This is an empirical question this study cannot answer from reading AgentDojo's source code alone** - it depends on Groq's specific serving/tokenization configuration for `llama-3.3-70b-versatile`, which is not publicly documented in enough detail to predict confidently either way.

**Consequences for future phases:** This category will still be included in the corpus for completeness and literature grounding, but its results will be treated with more caution than the other five - a 0% ASR here is ambiguous between "the defense works" and "this attack surface doesn't exist on Groq's stack at all".

**Instantiation in this study:** file-content channels (most room to embed a multi-token structural payload without looking obviously malformed in a one-line field).

---

## 3. What Falls Outside This Taxonomy

| Item | Source | Why excluded from this taxonomy |
|---|---|---|
| Indirect prompt injection as a delivery mechanism itself | [1, 2, 3] | This is *how* an attack arrives, not what it looks like - covered in [`threat_model.md`](threat_model.md) §3, not here. |
| Multi-modal (image-based) injection | [1] | This study's three domains have no image-processing tool in scope; not a reachable surface here. |
| "Hacking prompt reinforcement" as a benchmarked variable | [3] | This isn't a separate category - it's `direct_override` with a specific reinforcement phrase prepended. Treated as a variant within `direct_override`'s corpus entries, not its own category. |
| Adaptive attacks using victim/model metadata | [2] | This is a *targeting refinement* technique (personalizing a payload using the victim's or model's name) applicable on top of any of the six categories, not a category on its own. Relevant to future phases' adaptive-attack design, not to initial corpus tagging. |
| DoS-style payloads (swear words, CAPTCHA requests, illegal-content warnings forcing task failure) | [2] | Out of scope per [`threat_model.md`](threat_model.md) §4 - Availability is not measured by this study. |
| `ASI02`-`ASI04`, `ASI06`, `ASI07` (tool-layer exploitation, supply chain, memory poisoning, inter-agent comms) | [5] | These target architecture layers (tool schemas, registries, persistent memory, multi-agent messaging) this study's single-agent, single-session, mocked-tool design doesn't have. Addressed in [`threat_model.md`](threat_model.md) §5, §8. |
| Forged Agent Persona / Synthetic Identity Injection | [5] | See §2.2 - excluded from `role_play_persona` specifically; no multi-agent architecture exists in this study. |
| Goal-Lock Drift via Scheduled Prompts | [5] | See §2.4 - excluded from `multi_step_sleeper` specifically; single-session architecture only. |

---

## 4. Corpus Construction Reference

Quick-reference summary for tagging `src/payloads/corpus.json` entries.

| Category | Best-suited channels | Domains where fully reachable |
|---|---|---|
| `direct_override` | Any (email, file, transaction memo, chat) | Workspace, Banking, Slack |
| `role_play_persona` | Any, most natural in longer-form content | Workspace, Banking, Slack |
| `encoding_obfuscation` | File content | Workspace, Banking |
| `multi_step_sleeper` | Chat + web (trigger/fetch pair); file-staging elsewhere | Slack (full pattern); Workspace, Banking (file-staging variant only) |
| `fake_system_message` | File, email; less natural in short memo fields | Workspace, Banking, Slack |
| `chat_template_abuse` | File content | Workspace, Banking, Slack (empirically uncertain everywhere - §2.6) |

Target ~20-25 total payloads across these six categories, weighted toward `direct_override`, `role_play_persona`, and `encoding_obfuscation` as the categories with the clearest, most-evidenced technique base across sources - and correspondingly lighter on `chat_template_abuse` given its documented empirical uncertainty above.

---

## References

[1] K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz, "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection," arXiv preprint arXiv:2302.12173, 2023.

[2] E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, and F. Tramèr, "AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents," arXiv preprint arXiv:2406.13352, 2024.

[3] Q. Zhan, Z. Liang, Z. Ying, and D. Kang, "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents," arXiv preprint arXiv:2403.02691, 2024.

[4] OWASP Foundation, "OWASP Top 10 for Large Language Model Applications (2025)," 2025. [Online]. Available: https://owasp.org/www-project-top-10-for-large-language-model-applications/.

[5] OWASP Foundation, "OWASP Top 10 for Agentic Applications for 2026," 2026. [Online]. Available: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/.