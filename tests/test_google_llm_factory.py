"""No-network tests for Gemini request pacing and quota classification."""

from __future__ import annotations

import unittest

from google.genai import types as genai_types
from google.genai.errors import ClientError

from src.llm_providers.google_llm_factory import (
    FALLBACK_MODEL,
    GEMMA4_26B_MODEL,
    GEMMA4_26B_RPD_LIMIT,
    GEMMA4_26B_RPM_LIMIT,
    GEMMA4_26B_TPM_LIMIT,
    GEMMA4_TOKEN_SAFETY_TARGET,
    HTTP_REQUEST_TIMEOUT_MS,
    MIN_REQUEST_INTERVAL_SECONDS,
    PRIMARY_MODEL,
    PRIMARY_RPD_LIMIT,
    PRIMARY_RPM_LIMIT,
    PRIMARY_TPM_LIMIT,
    Gemini3LLM,
    RequestBudgetExceeded,
    RequestRateLimiter,
    TokenWindowPacer,
    approximate_request_tokens,
    classify_quota_error,
    is_retryable_server_error,
)


class _FakeTime:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class _FakeModels:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def generate_content(self, **_: object) -> object:
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _FakeClient:
    def __init__(self, outcomes: list[object]) -> None:
        self.models = _FakeModels(outcomes)


class GoogleLLMFactoryTests(unittest.TestCase):
    def test_rate_limiter_spaces_every_request_start(self) -> None:
        fake_time = _FakeTime()
        limiter = RequestRateLimiter(
            MIN_REQUEST_INTERVAL_SECONDS,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )

        limiter.wait_before_request()
        limiter.wait_before_request()
        limiter.wait_before_request()

        self.assertEqual([4.5, 4.5], fake_time.sleeps)
        self.assertEqual(3, limiter.requests_started)

    def test_recorded_models_and_primary_quota_are_explicit(self) -> None:
        self.assertEqual("gemini-3.5-flash-lite", PRIMARY_MODEL)
        self.assertEqual("gemini-3.1-flash-lite", FALLBACK_MODEL)
        self.assertEqual((15, 250_000, 500), (PRIMARY_RPM_LIMIT, PRIMARY_TPM_LIMIT, PRIMARY_RPD_LIMIT))
        self.assertEqual("gemma-4-26b-a4b-it", GEMMA4_26B_MODEL)
        self.assertEqual(
            (30, 16_000, 14_400),
            (GEMMA4_26B_RPM_LIMIT, GEMMA4_26B_TPM_LIMIT, GEMMA4_26B_RPD_LIMIT),
        )
        self.assertEqual(14_000, GEMMA4_TOKEN_SAFETY_TARGET)
        self.assertEqual(120_000, HTTP_REQUEST_TIMEOUT_MS)

    def test_request_budget_stops_before_an_excess_api_call(self) -> None:
        fake_time = _FakeTime()
        limiter = RequestRateLimiter(
            0.0,
            max_requests=2,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )

        limiter.wait_before_request()
        limiter.wait_before_request()
        with self.assertRaises(RequestBudgetExceeded):
            limiter.wait_before_request()

        self.assertEqual(2, limiter.requests_started)

    def test_defer_extends_the_next_request_wait(self) -> None:
        fake_time = _FakeTime()
        limiter = RequestRateLimiter(
            MIN_REQUEST_INTERVAL_SECONDS,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )

        limiter.wait_before_request()
        limiter.defer(65.0)
        limiter.wait_before_request()

        self.assertEqual([65.0], fake_time.sleeps)

    def test_quota_classifier_distinguishes_request_token_and_day_metrics(self) -> None:
        rpm = ClientError(
            429,
            {"error": {"status": "RESOURCE_EXHAUSTED", "details": [
                {"quotaId": "GenerateRequestsPerMinutePerProjectPerModel-FreeTier"}
            ]}},
        )
        rpd = ClientError(
            429,
            {"error": {"status": "RESOURCE_EXHAUSTED", "details": [
                {"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier"}
            ]}},
        )
        tpm = ClientError(
            429,
            {"error": {"status": "RESOURCE_EXHAUSTED", "details": [
                {"quotaId": "GenerateContentInputTokensPerModelPerMinute-FreeTier"}
            ]}},
        )
        unknown = ClientError(429, {"error": {"status": "RESOURCE_EXHAUSTED"}})

        self.assertEqual("rpm", classify_quota_error(rpm))
        self.assertEqual("tpm", classify_quota_error(tpm))
        self.assertEqual("rpd", classify_quota_error(rpd))
        self.assertEqual("unknown", classify_quota_error(unknown))

    def test_rpm_error_waits_and_retries(self) -> None:
        fake_time = _FakeTime()
        limiter = RequestRateLimiter(
            0.0,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )
        rpm = ClientError(
            429,
            {"error": {"status": "RESOURCE_EXHAUSTED", "details": [
                {"quotaId": "GenerateRequestsPerMinutePerProjectPerModel-FreeTier"}
            ]}},
        )
        expected = object()
        client = _FakeClient([rpm, expected])
        llm = Gemini3LLM("test-model", client, rate_limiter=limiter)  # type: ignore[arg-type]

        actual = llm._generate_content([], genai_types.GenerateContentConfig())

        self.assertIs(expected, actual)
        self.assertEqual(2, client.models.calls)
        self.assertEqual([65.0], fake_time.sleeps)

    def test_rpd_error_is_not_retried(self) -> None:
        fake_time = _FakeTime()
        limiter = RequestRateLimiter(
            0.0,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )
        rpd = ClientError(
            429,
            {"error": {"status": "RESOURCE_EXHAUSTED", "details": [
                {"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier"}
            ]}},
        )
        client = _FakeClient([rpd])
        llm = Gemini3LLM("test-model", client, rate_limiter=limiter)  # type: ignore[arg-type]

        with self.assertRaises(ClientError):
            llm._generate_content([], genai_types.GenerateContentConfig())

        self.assertEqual(1, client.models.calls)
        self.assertEqual([], fake_time.sleeps)

    def test_http_500_client_error_is_retried_before_reaching_agentdojo(self) -> None:
        fake_time = _FakeTime()
        limiter = RequestRateLimiter(
            0.0,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )
        internal_error = ClientError(
            500, {"error": {"status": "INTERNAL", "message": "Internal error"}}
        )
        expected = object()
        client = _FakeClient([internal_error, expected])
        llm = Gemini3LLM("test-model", client, rate_limiter=limiter)  # type: ignore[arg-type]

        actual = llm._generate_content([], genai_types.GenerateContentConfig())

        self.assertIs(expected, actual)
        self.assertEqual(2, client.models.calls)
        self.assertEqual([4.5], fake_time.sleeps)
        self.assertTrue(is_retryable_server_error(internal_error))

    def test_client_errors_outside_the_5xx_range_are_not_transient(self) -> None:
        self.assertFalse(
            is_retryable_server_error(
                ClientError(400, {"error": {"status": "INVALID_ARGUMENT"}})
            )
        )

    def test_tpm_error_waits_and_retries_with_the_rpm_bound(self) -> None:
        fake_time = _FakeTime()
        limiter = RequestRateLimiter(
            0.0,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )
        tpm = ClientError(
            429,
            {"error": {"status": "RESOURCE_EXHAUSTED", "details": [
                {"quotaId": "GenerateTokensPerMinutePerProjectPerModel-FreeTier"}
            ]}},
        )
        expected = object()
        client = _FakeClient([tpm, expected])
        llm = Gemini3LLM("test-model", client, rate_limiter=limiter)  # type: ignore[arg-type]

        actual = llm._generate_content([], genai_types.GenerateContentConfig())

        self.assertIs(expected, actual)
        self.assertEqual(2, client.models.calls)
        self.assertEqual([65.0], fake_time.sleeps)

    def test_token_window_pacer_waits_before_cumulative_limit(self) -> None:
        fake_time = _FakeTime()
        pacer = TokenWindowPacer(
            10_000,
            window_seconds=60.0,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )

        self.assertEqual(0.0, pacer.wait_before_tokens(6_000))
        self.assertEqual(60.0, pacer.wait_before_tokens(5_000))
        self.assertEqual([60.0], fake_time.sleeps)

    def test_request_token_estimate_includes_messages_and_tools_without_mutation(self) -> None:
        messages = [genai_types.Content(role="user", parts=[genai_types.Part(text="x" * 900)])]
        config = genai_types.GenerateContentConfig(
            tools=[genai_types.Tool(function_declarations=[])]
        )
        before = repr(messages)

        estimate = approximate_request_tokens(messages, config)

        self.assertGreater(estimate, 256)
        self.assertEqual(before, repr(messages))


if __name__ == "__main__":
    unittest.main()
