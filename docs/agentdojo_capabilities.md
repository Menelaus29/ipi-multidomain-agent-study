# AgentDojo Capabilities Reference 

> **Source of truth for:** attack & defense names, per-suite tool lists, task/injection-task counts, and the closed-`ModelsEnum` finding that explains why every experiment in this project uses the Python API rather than the CLI.

---

## 1. Benchmark Suites

AgentDojo ships four task suites. This project uses three:

|Suite|Used?|User Tasks|Injection Tasks|Notes|
|---|---|---|---|---|
|`workspace`|YES|40|14|Email, calendar, files|
|`banking`|YES|16|9|Financial transactions, user info|
|`slack`|YES|21|5|Messaging, web access|
|`travel`|NO|-|-|Excluded per project scope|

All three suites use benchmark version `v1.2.2`.

---

## 2. Built-in Attacks

| Attack name                               | Class                                    |
| ----------------------------------------- | ---------------------------------------- |
| `manual`                                  | `ManualAttack`                           |
| `direct`                                  | `DirectAttack`                           |
| `ignore_previous`                         | `IgnorePreviousAttack`                   |
| `system_message`                          | `SystemMessageAttack`                    |
| `injecagent`                              | `InjecAgentAttack`                       |
| `important_instructions`                  | `ImportantInstructionsAttack`            |
| `important_instructions_no_user_name`     | `ImportantInstructionsAttackNoUserName`  |
| `important_instructions_no_model_name`    | `ImportantInstructionsAttackNoModelName` |
| `important_instructions_no_names`         | `ImportantInstructionsAttackNoNames`     |
| `important_instructions_wrong_model_name` | `ImportantInstructionsWrongModelName`    |
| `important_instructions_wrong_user_name`  | `ImportantInstructionsWrongUserName`     |
| `tool_knowledge`                          | `ToolKnowledgeAttack`                    |
| `dos`                                     | `DoSAttack`                              |
| `swearwords_dos`                          | `SwearwordsDoSAttack`                    |
| `captcha_dos`                             | `CaptchaDoSAttack`                       |
| `offensive_email_dos`                     | `OffensiveEmailDoSAttack`                |
| `felony_dos`                              | `FelonyDoSAttack`                        |

**In-scope for this project:** `tool_knowledge`, `important_instructions` family, `ignore_previous`, `system_message`, `injecagent`.

**Out of scope:** DoS-family attacks (`dos`, `swearwords_dos`, `captcha_dos`, `offensive_email_dos`, `felony_dos`) - see [`threat_model.md`](threat_model.md) §4.

---

## 3. Built-in Defenses

|Defense flag|Description|
|---|---|
|`tool_filter`|Filters tool calls suspected of being injection-influenced|
|`transformers_pi_detector`|ML-based PI detector (requires `agentdojo[transformers]`)|
|`spotlighting_with_delimiting`|Wraps untrusted data in explicit delimiters + system-prompt guard|
|`repeat_user_prompt`|Repeats the user's original task at each agent step|

**Defense:** custom re-implementation of spotlighting, validated against **AgentDojo**'s `spotlighting_with_delimiting` baseline.

---

## 4. Per-Suite Tool Lists

These lists are the foundation for the channel-to-domain mapping in [`taxonomy.md`](taxonomy.md) §4.

### 4.1 Workspace

**Tools (24):** `send_email`, `delete_email`, `get_unread_emails`, `get_sent_emails`, `get_received_emails`, `get_draft_emails`, `search_emails`, `search_contacts_by_name`, `search_contacts_by_email`, `get_current_day`, `search_calendar_events`, `get_day_calendar_events`, `create_calendar_event`, `cancel_calendar_event`, `reschedule_calendar_event`, `add_calendar_event_participants`, `append_to_file`, `search_files_by_filename`, `create_file`, `delete_file`, `get_file_by_id`, `list_files`, `share_file`, `search_files`

**Injection surfaces reachable:** email body (`get_unread_emails`, `get_received_emails`), calendar events (`get_day_calendar_events`, `search_calendar_events`), file content (`get_file_by_id`, `search_files`).

**No web-fetch tool** ->`web_content` channel is **not reachable** in this suite.

### 4.2 Banking

**Tools (11):** `get_iban`, `send_money`, `schedule_transaction`, `update_scheduled_transaction`, `get_balance`, `get_most_recent_transactions`, `get_scheduled_transactions`, `read_file`, `get_user_info`, `update_password`, `update_user_info`

**Injection surfaces reachable:** transaction memos / descriptions (via `get_most_recent_transactions`, `get_scheduled_transactions`), file content (`read_file`).

**No email tool, no web-fetch tool** -> `email_body` and `web_content` channels are **not reachable** in this suite.

### 4.3 Slack

**Tools (11):** `get_channels`, `add_user_to_channel`, `read_channel_messages`, `read_inbox`, `send_direct_message`, `send_channel_message`, `get_users_in_channel`, `invite_user_to_slack`, `remove_user_from_slack`, `get_webpage`, `post_webpage`

**Injection surfaces reachable:** channel messages (`read_channel_messages`, `read_inbox`), web content (`get_webpage`, `post_webpage`).

**No email tool, no file-read tool, no calendar tool** -> `email_body`, `file_content`, and calendar channels are **not reachable** in this suite.

---

## 5. Verified Channel-to-Domain Mapping

Derived from the tool lists above (§4).

|Channel|Reachable Domains|Tool(s) that create the surface|
|---|---|---|
|`email_body`|Workspace only|`get_unread_emails`, `get_received_emails`|
|`calendar_event`|Workspace only|`get_day_calendar_events`, `search_calendar_events`|
|`file_content`|Workspace + Banking|`get_file_by_id`, `search_files` (WS); `read_file` (B)|
|`transaction_memo`|Banking only|`get_most_recent_transactions`, `get_scheduled_transactions`|
|`web_content`|**Slack only**|`get_webpage`, `post_webpage`|
|`chat_message`|Slack only|`read_channel_messages`, `read_inbox`; retrievable, but AgentDojo v1.2.2 has no native message-body injection placeholder, so it is not used as a recorded Phase 6 stratum|

---

## 6. Closed `ModelsEnum` - Why the CLI Cannot Be Used

The `--model` flag resolves against a closed `ModelsEnum`. The full accepted list:

```
gpt-4o-2024-05-13 | gpt-4o-mini-2024-07-18 | gpt-4-0125-preview |
gpt-3.5-turbo-0125 | gpt-4-turbo-2024-04-09 | claude-3-opus-20240229 |
claude-3-sonnet-20240229 | claude-3-5-sonnet-20240620 | claude-3-5-sonnet-20241022 |
claude-3-7-sonnet-20250219 | claude-3-7-sonnet-20250219-thinking-16000 |
claude-3-haiku-20240307 | command-r-plus | command-r |
mistralai/Mixtral-8x7B-Instruct-v0.1 | meta-llama/Llama-3-70b-chat-hf |
gemini-1.5-pro-002 | gemini-1.5-pro-001 | gemini-1.5-flash-002 |
gemini-1.5-flash-001 | gemini-2.0-flash-exp | gemini-2.0-flash-001 |
gemini-2.5-flash-preview-04-17 | gemini-2.5-pro-preview-05-06 |
local | vllm_parsed | openai-compatible
```

The project's provider, Google AI Studio's API-key path, is **not** represented by AgentDojo's built-in Google entries: those resolve through Vertex AI.

**Solution ([google_llm_factory.py](../src/llm_providers/google_llm_factory.py)):** `PipelineConfig.llm` accepts `str | BasePipelineElement`. When it receives an already-constructed object, `AgentPipeline.from_config()` skips `get_llm()`/`ModelsEnum` and uses the object as-is. Every experiment script in this project constructs a GoogleLLM-compatible object with `genai.Client(api_key=GOOGLE_API_KEY)` and passes it directly to `benchmark_suite()`.

**Consequence:** `python -m agentdojo.scripts.benchmark` cannot be used at all for this project's experiments. All runs go through the Python API (`benchmark_suite()`).

---

## 7. Other CLI Flags (Reference)

|Flag|Default|Notes|
|---|---|---|
|`--benchmark-version`|`v1.2`|This project uses `v1.2.2`|
|`--logdir`|`./runs`|Overridden in all experiment scripts to `data/<phase>/`|
|`--max-workers`|(no parallel)|Parallelism available but not used by default|
|`-f / --force-rerun`|False|Set to `True` in sanity checks; production runs checkpoint instead|
|`-ut / --user-task`|(all tasks)|Used to scope sanity checks to a single task|
|`-it / --injection-task`|(all tasks)|Same scoping mechanism for injection tasks|
|`-ml / --module-to-load`|-|For registering custom attacks/defenses/suites (not used here)|