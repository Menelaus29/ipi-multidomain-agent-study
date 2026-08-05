# Threat Model

**Scope of this document:** the attacker model, trust boundary, delivery methods, and threats actually exercised by this study's three AgentDojo domains - Workspace, Banking, Slack - evaluated against a single primary model (`llama-3.3-70b-versatile`) across undefended, defended, and adaptive-attack conditions. 

---

## 1. Attacker Model

### 1.1 Capabilities and access

The attacker in this study **cannot interact with the agent's interface directly**. Instead, the attacker's only capability is to **place natural-language content inside a data source the agent's tools will later retrieve**, e.g., an email that arrives in an inbox, a file stored in a workspace drive, a transaction memo, a Slack message or channel post, or (Slack only) a web page the agent is instructed to fetch [1, 2, 3]. This requires no access to the model, no ML expertise, and no privileged system access [1] - only the ability to get content into one of these retrievable locations, which in most real deployments is trivial (anyone can send an email or post to a shared channel).

The attacker cannot observe the agent's internal reasoning or tool-call trace, and generally cannot observe the outcome of a successful attack unless the attack itself includes an exfiltration step (e.g., instructing the agent to email data back to an attacker-controlled address) [3]. The attack is therefore blind by default: success is inferred by the attacker only through side effects the attack itself causes.

### 1.2 Attacker goal

The attacker's goal in this study is to make the agent execute **an unauthorized secondary task** that the legitimate user never requested, while the agent continues to appear (to the user) as if it is still working on the original task. Concretely, this maps to AgentDojo's own injection-task design [2]: unauthorized fund transfers or scheduled payments (Banking), unauthorized emails or file-sharing actions (Workspace), and unauthorized messages, channel posts, or membership changes (Slack).

This is the mechanism OWASP's Agentic Top 10 names **`ASI01` - Agent Goal Hijack**: manipulated input redirects the agent's goals, planning, and multi-step behavior [5], and what OWASP's LLM Top 10 names **`LLM01` - Prompt Injection**, specifically its indirect variant, where the LLM accepts input from an attacker-controlled external source and is hijacked into acting as a "confused deputy" [4]. These two IDs are this study's primary framing and are cited throughout the rest of this document and the eventual report.

---

## 2. Trust Boundary

### 2.1 General definition

Across all three primary sources, the trust boundary is described the same way at its core: the point where **data retrieved at inference time** (from a tool call) **is handed to the LLM alongside its actual instructions**, with no structural separation between the two. Greshake et al. describe this as processing retrieved data as if it were arbitrary code: the model fails to separate code (instructions) from data (content) [1]. AgentDojo places this boundary specifically between untrusted tool outputs and the agent's internal planning/reasoning context [2]. InjecAgent places it between tool responses and the agent's reasoning scratchpad, which records thoughts, actions, and observations used to decide the next tool call [3]. All three are describing the same boundary from slightly different architectural vantage points; this study adopts AgentDojo's framing directly, since it's the framework the experiments are built on.

### 2.2 Where the boundary sits in each domain

The boundary is instantiated at the return value of specific tool calls, verified directly against AgentDojo's actual tool implementations:

| Domain | Tool calls that cross the boundary | Untrusted content that enters agent context |
|---|---|---|
| **Workspace** | `get_unread_emails`, `get_received_emails`, `search_emails`, `search_files`, `get_file_by_id`, `search_calendar_events` | Email bodies, file contents, calendar event titles/descriptions |
| **Banking** | `get_most_recent_transactions`, `get_scheduled_transactions`, `read_file` | Transaction memos/descriptions, file contents |
| **Slack** | `read_channel_messages`, `read_inbox`, `get_webpage` | Channel messages, direct messages, fetched web-page content |

Slack is architecturally distinct from the other two: it is the only domain with a live content-fetching tool (`get_webpage`), which means it is the only domain where Greshake's "passive, by-retrieval" delivery method [1] is actually reachable. Workspace and Banking have no such tool - their untrusted content always arrives because *something* (an email, a transaction) was actively sent to reach the agent, not passively indexed and later retrieved.

---

## 3. Delivery Methods

Greshake et al. categorize how an injection reaches the model into four methods [1]:

| Method | Definition [1] | Instantiation in this study |
|---|---|---|
| **Passive (by retrieval)** | Content is placed in a public location an automated query is likely to retrieve (e.g., SEO-optimized poisoned pages). | **Slack only**, via `get_webpage`. Not reachable in Workspace or Banking - neither has a fetch/search-the-web tool. |
| **Active** | Content is actively sent to reach the agent (e.g., an email delivered to an inbox). | **Workspace**: an email arriving via `get_unread_emails`/`get_received_emails`. **Banking**: a transaction with a malicious memo arriving via `get_most_recent_transactions`. **Slack**: a message arriving via `read_channel_messages`/`read_inbox`. This is the dominant delivery method across all three domains. |
| **User-driven** | The legitimate user is tricked into pasting or entering attacker content themselves. | **Not modeled by this study.** AgentDojo's injection tasks are attacker-to-tool-output by design, not user-mediated. |
| **Hidden / multi-stage** | The payload is encoded, or a small initial injection instructs the agent to fetch a larger secondary payload. | Maps onto `encoding_obfuscation` and the taxonomy-only `multi_step_sleeper` category in [`taxonomy.md`](taxonomy.md). Encoding is instantiated via file content; staged attacks are excluded from the empirical corpus because the installed suites do not expose a genuine attacker-controlled trigger/second-stage pair. |

---

## 4. Broader Threat Landscape - Scoped to This Study

Greshake et al. categorize the *impact* an indirect prompt injection can have into six threat classes [1]. This study does not test all six - AgentDojo is a sandboxed benchmark with mocked tools and no real infrastructure, so several of Greshake's classes describe real-world consequences this study has no mechanism to produce:.

| Threat class [1] | In this study? | Reasoning |
|---|---|---|
| **Information gathering** (personal data, credentials, chat leakage) | **IN SCOPE** | Directly instantiated by AgentDojo's data-exfiltration injection tasks - e.g., leaking email content or banking/user info to an attacker-controlled recipient. |
| **Fraud** (phishing, scams, masquerading) | **IN SCOPE** | Banking's unauthorized `send_money`/`schedule_transaction` tasks are direct financial fraud. Workspace's unauthorized `send_email` tasks are phishing-adjacent. |
| **Intrusion** (persistence, remote control, privilege escalation) | **OUT OF SCOPE** | No real backing infrastructure exists to persist in or escalate privileges within; AgentDojo's tools are mocked, stateless-between-runs simulations. |
| **Malware** (prompts as worms, spreading to other users/agents) | **OUT OF SCOPE** | This study is single-session and single-agent. There is no mechanism here for an injected payload to write itself into content another user's agent instance later processes. |
| **Manipulated content** (disinformation, biased summaries, data hiding) | **PARTIALLY IN SCOPE** | The agent's own outputs can be hijacked to post or forward attacker-serving content (e.g., a hijacked `post_webpage`/`send_channel_message` in Slack) - this narrow form is in scope. Broader claims about disinformation reaching many end-users at scale are not modeled here. |
| **Availability** (DoS, forced excess computation) | **OUT OF SCOPE** | This study measures task-success/failure (Attack Success Rate), not latency or resource exhaustion. No DoS-style payloads are included in the corpus. |

---

## 5. Industry Framework Citations


**Primary framing:**
- **`ASI01` - Agent Goal Hijack** [5]: manipulated input (via injection) redirects the agent's goals and multi-step behavior. This is the mechanism this entire study measures.
- **`LLM01` - Prompt Injection** [4], indirect variant: the LLM accepts attacker-controlled external input and acts as a confused deputy.

**Enabling condition (why a successful hijack translates into real impact):**
- **`ASI02` - Tool Misuse & Exploitation** [5]: an agent operating within its *authorized* privileges applies a legitimate tool in an unsafe or unintended way, for example when a hijacked agent calls `send_money` or `send_email` with attacker-supplied arguments. The agent was never granted permission it shouldn't have; the permission it already has is simply misdirected.
- **`LLM08` - Excessive Agency** [4]: the root vulnerability class describing why granting an agent broad tool functionality (delete, transfer, send) creates the blast radius that `ASI02`-style misuse exploits.

**Related, explicitly out of scope:**
- **`ASI06` - Memory & Context Poisoning** [5]: describes injection that *permanently* corrupts a persistent memory or RAG store, altering agent behavior across *future sessions*. AgentDojo tasks are single-session with no persistent memory store between runs - this study has no mechanism to produce or measure `ASI06`-style persistence.
- **Multi-agent identity/trust risks** - `ASI03` (Identity & Privilege Abuse, including cross-agent "confused deputy" trust exploitation) and `ASI07` (Insecure Inter-Agent Communication), along with the general concept of a forged/impersonated peer-agent identity - describe attacks between multiple communicating LLM agents. All three of this study's domains involve exactly **one** agent calling deterministic tool functions; there is no second agent to impersonate or communicate with.
---

## 6. Assets at Risk, Per Domain

**Workspace**
- Email thread contents and contact list (`search_contacts_by_name/email`)
- Calendar events and their participant lists (`add_calendar_event_participants` - meaning unauthorized participants could be added to a private event, not just data leaked)
- Files, including sharing permissions (`share_file` - a hijacked call here grants an attacker-controlled party access to a file, not just its contents)

**Banking**
- Account balance and transaction history
- IBAN and user PII (`get_user_info`)
- **Credentials themselves**: `update_password` and `update_user_info` exist as tools in this suite, meaning a hijacked agent could change the account's password or personal info directly - an account-takeover path, not just a financial-fraud path. This is a higher-stakes asset than "money" alone and is worth explicit emphasis in the eventual report.

**Slack**
- Channel and DM contents
- **Channel/workspace membership itself**: `add_user_to_channel`, `remove_user_from_slack`, `invite_user_to_slack` exist as tools, meaning a hijacked agent could add an attacker to a private channel or remove a legitimate member - an access-control asset distinct from message content.
- Content of any web page the agent is induced to fetch or post (`get_webpage`/`post_webpage`)

---

## 7. Affected Parties

Adapted from Greshake et al.'s general framing [1], tagged against what this study actually models:

| Party | Modeled in this study? |
|---|---|
| **End-users** (the simulated Workspace/Banking/Slack account owner) | Yes - every AgentDojo injection task is defined in terms of harm to this simulated user. |
| **Automated systems** (the agent itself, and the tool integrations it calls) | Yes - this is the direct object of every attack in this study. |
| **Developers** (of the agent/defense) | Indirectly - the defense built in Phase 8-9 stands in for this party's mitigation work. |
| **The LLM/service itself** (as a target of availability attacks) | No - see §4, Availability is explicitly out of scope. |

---

## 8. Out-of-Scope Summary

- Intrusion/persistence, malware propagation, availability/DoS (§4)
- Cross-session memory/context poisoning (`ASI06`) - single-session architecture only
- Multi-agent identity spoofing and inter-agent trust exploitation (`ASI03`/`ASI07`-adjacent) - single-agent architecture only
- User-driven injection delivery (§3) - not how AgentDojo's injection tasks are structured
- Passive/by-retrieval delivery in Workspace and Banking (§3) - no fetch/search tool exists in either suite; only Slack can instantiate this method

---

## References

[1] K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz, "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection," arXiv preprint arXiv:2302.12173, 2023.

[2] E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, and F. Tramèr, "AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents," arXiv preprint arXiv:2406.13352, 2024.

[3] Q. Zhan, Z. Liang, Z. Ying, and D. Kang, "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents," arXiv preprint arXiv:2403.02691, 2024.

[4] OWASP Foundation, "OWASP Top 10 for Large Language Model Applications (2025)," 2025. [Online]. Available: https://owasp.org/www-project-top-10-for-large-language-model-applications/.

[5] OWASP Foundation, "OWASP Top 10 for Agentic Applications for 2026," 2026. [Online]. Available: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/.
