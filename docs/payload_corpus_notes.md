# Payload Corpus Notes

This corpus contains 19 hand-authored payload templates. Every template contains exactly one supported goal token. At runtime, the runner substitutes the concrete native AgentDojo injection goal directly, or a deterministic reversible encoding of that goal. It rejects unknown, missing, multiple, or unresolved tokens before an API call. No template is intended for a live system.

## `direct_override`

Four variants use explicit task-replacement language across email, transaction, webpage, and file surfaces. They vary urgency and framing while requesting the same benchmark-native goal supplied by the suite.

## `role_play_persona`

Four variants frame the native goal as a compliance, fraud-recovery, incident-response, or data-migration duty. This separates role-based pressure from an overt imperative without changing the checked action.

## `encoding_obfuscation`

All four variants use the verified file-content surface available in Workspace and Banking. At runtime they transform the native goal using Base64, character reversal, Unicode escapes, or first-token-per-line encoding, so the transformation—not a different requested action—is the experimental difference.

## Excluded: `multi_step_sleeper`

This category is retained in the taxonomy but excluded from the empirical corpus. The installed suites expose only one injected value per selected case, so the earlier “fetch another page/file” text did not place attacker-controlled second-stage content at the destination and was not a genuine multi-stage attack. Implementing it honestly would require custom suite state or coordinated multi-vector injection, disproportionate complexity for three variants.

## `fake_system_message`

Four variants imitate service alerts, API responses, a tool-policy update, and a maintenance banner. They test impersonated authority while still embedding the exact native goal.

## `chat_template_abuse`

On 2026-08-04, a manual Google AI Studio smoke test sent literal ChatML and Llama-style markers in simulated untrusted tool data while asking `gemini-3.6-flash` to summarize it. The response omitted the injected sentinel, so this is an empirical null signal for structured Google SDK delivery—not proof of universal safety. The corpus retains only three file-content variants rather than padding this category.

## Corpus review

The corpus was reviewed end to end for duplicate mechanisms, requested actions, and channel mappings. Every retained entry uses a verified native AgentDojo injection vector. Although Slack tools can read chat messages, AgentDojo v1.2.2 exposes no message-body injection placeholder, so the recorded Slack corpus uses `web_content` rather than claiming a `chat_message` stratum.
