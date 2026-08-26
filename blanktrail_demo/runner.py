"""Orchestration: turn a form into a stream of NDJSON events.

Serial by default; optionally concurrent across up to 16 workers (see
RunPlan.workers). Every target is isolated: an exception inside one becomes
an ERROR for THAT target, not a dead run — true whether targets run one at a
time or several at once.
"""

from __future__ import annotations

import random
import ssl
import time
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .btapi import ApiError, BlankTrailApi, open_body
from .detect import STAT_KEY, verdict
from .endpoints import ApiEndpoint, Endpoint, PresetEndpoint, tcp_reachable
from .proxyurl import normalize, parse_list
from .targets import Target, parse_targets
from .transport import make_fetcher, probe
from .trust import SOURCE_API, SOURCE_SYSTEM, Trust, TrustError, build

LANE_A_MODES = ("direct", "upstream", "off")


@dataclass
class RunPlan:
    targets: list[Target]
    lane_a_mode: str
    lane_a_proxy: str | None
    endpoint: Endpoint
    trust: Trust
    trust_source: str
    protocol: str
    timeout: int
    delay_min: float
    delay_max: float
    # How many targets run at once. 1 (serial) is the default — see the
    # comment at its clamp in build_run() for why — and 16 is the ceiling.
    # Pacing (delay_min/delay_max) is applied PER WORKER, not shared across
    # them: with N workers the effective aggregate request rate is roughly
    # N times what these two numbers alone suggest.
    workers: int = 1
    warnings: list[str] = field(default_factory=list)


def _clamp(value, low, high, default):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def build_run(config: Mapping) -> tuple[RunPlan | None, list[str]]:
    """Validate the form. Returns (plan, errors); a non-empty error list means
    nothing ran."""
    errors: list[str] = []
    warnings: list[str] = []

    # Concurrency is an explicit opt-in, not the default. This tool is a
    # measurement instrument: delay_min/delay_max exist so a run does not
    # hammer a target, and running targets one at a time is what makes that
    # promise hold without the operator having to think about it — going
    # concurrent is a deliberate choice they make, not something the tool
    # nudges them toward. Out-of-range values are clamped rather than
    # rejected: a stray 0 or 200 in the form should not fail the whole run
    # over one bad number.
    workers = int(_clamp(config.get("workers"), 1, 16, 1))

    targets, target_errors = parse_targets(str(config.get("targets") or ""))
    for parse_error in target_errors:
        errors.append(f"line {parse_error.line_no}: {parse_error.error} "
                      f"({parse_error.text})")
    if not targets and not errors:
        errors.append("no targets: paste one URL per line")

    lane_a_mode = str(config.get("lane_a") or "upstream")
    if lane_a_mode not in LANE_A_MODES:
        errors.append(f"unknown baseline lane mode: {lane_a_mode!r}")
    lane_a_proxy = None
    if lane_a_mode == "upstream":
        lane_a_proxy = normalize(str(config.get("lane_a_upstream") or ""))
        if not lane_a_proxy:
            errors.append("baseline lane is set to 'upstream' but no upstream proxy was "
                          "given")
    elif lane_a_mode == "direct":
        warnings.append("baseline lane runs direct: the two lanes leave from different "
                        "egress IPs, so the comparison mixes the IP's contribution with "
                        "the fingerprint's")
    else:
        warnings.append("baseline lane is off: a PASS proves BlankTrail got through, not "
                        "that the target challenges anyone")

    api: BlankTrailApi | None = None
    endpoint: Endpoint | None = None
    lane_b_mode = str(config.get("lane_b") or "preset")
    if lane_b_mode == "preset":
        urls, url_errors = parse_list(str(config.get("preset_urls") or ""))
        for parse_error in url_errors:
            errors.append(f"proxy list line {parse_error.line_no}: {parse_error.error}")
        endpoint = PresetEndpoint(urls)
    elif lane_b_mode == "api":
        api = BlankTrailApi(str(config.get("api_base") or "http://127.0.0.1:8891"),
                            str(config.get("api_key") or ""))
        try:
            # The form sends the port's protocol as protocol_b, because `protocol`
            # already means the HTTP client selector (h1/h2). Renaming it earlier
            # would overwrite that selector and silently pin every run to HTTP/2.
            body = open_body({**config, "protocol": config.get("protocol_b") or "http"})
        except ApiError as exc:
            errors.append(str(exc))
            body = {}
        endpoint = ApiEndpoint(api, body,
                               close_when_done=bool(config.get("close_when_done", True)),
                               workers=workers)
    else:
        errors.append(f"unknown BlankTrail lane mode: {lane_b_mode!r}")

    trust_source = str(config.get("trust_source") or SOURCE_SYSTEM)
    tls_disabled = bool(config.get("tls_disabled"))
    if tls_disabled:
        warnings.append("TLS verification is disabled: the verdicts no longer prove the "
                        "certificate chain is sound")
    ca_pem = None
    if not tls_disabled and trust_source == SOURCE_API:
        if api is None:
            errors.append("the 'Fetch from API' trust source needs the API lane mode")
        else:
            try:
                ca_pem = api.ca()
            except ApiError as exc:
                errors.append(f"could not fetch the CA: {exc}")
    trust: Trust | None = None
    if not errors:
        try:
            trust = build(trust_source, disabled=tls_disabled, ca_pem=ca_pem,
                          ca_path=str(config.get("ca_path") or ""))
        except (TrustError, ssl.SSLError) as exc:
            # A CA file that exists but is malformed is only rejected when
            # create_default_context parses it, which raises SSLError rather than
            # TrustError. Both mean the same thing to the user: the chosen trust
            # source cannot be used.
            errors.append(f"TLS trust source could not be used: {exc}")

    if errors or trust is None or endpoint is None:
        if api is not None:
            api.close()
        return None, errors

    delay_min = _clamp(config.get("delay_min"), 0, 60, 0)
    delay_max = max(delay_min, _clamp(config.get("delay_max"), 0, 60, 0))
    return RunPlan(
        targets=targets,
        lane_a_mode=lane_a_mode,
        lane_a_proxy=lane_a_proxy,
        endpoint=endpoint,
        trust=trust,
        trust_source=SOURCE_SYSTEM if tls_disabled else trust_source,
        protocol="h1" if str(config.get("protocol")) == "h1" else "h2",
        timeout=int(_clamp(config.get("timeout"), 5, 300, 60)),
        delay_min=delay_min,
        delay_max=delay_max,
        workers=workers,
        warnings=warnings,
    ), []


def run(plan: RunPlan) -> Iterator[dict]:
    """Emit the event stream. Never raises out of the generator."""
    no_baseline = plan.lane_a_mode == "off"
    stats = {"done": 0, "req": 0, "passed": 0, "failed": 0, "void": 0, "err": 0}
    started = time.time()

    def stats_event() -> dict:
        elapsed = max(0.001, time.time() - started)
        return {"type": "stats", "elapsed": int(elapsed),
                "rpm": round(stats["req"] * 60 / elapsed, 1), **stats}

    def pause() -> None:
        # Per WORKER, not shared across the run: each concurrent worker
        # sleeps delay_min..delay_max between its own requests, independent
        # of whatever any other worker is doing. With N workers the
        # effective aggregate request rate against the target is roughly N
        # times what these two numbers alone suggest — read them with the
        # worker count in mind.
        if plan.delay_max > 0:
            time.sleep(random.uniform(plan.delay_min, plan.delay_max))

    def process_target(index: int, target: Target) -> list[dict]:
        """Run one target start to finish; return its whole event block.

        Called from a worker thread when plan.workers > 1. Returns instead
        of yielding so the caller — the single writer of the stream — can
        hand the whole block over in one piece once this target is done:
        a target's target/log/result events must never have another
        target's events land between them, and collecting into a list
        (instead of yielding across threads) is what guarantees that
        regardless of completion order. See the "else" branch below.
        """
        events: list[dict] = []
        events.append({"type": "target", "n": index + 1, "total": len(plan.targets),
                       "id": target.id, "url": target.url})
        entry_a = entry_b = None
        fetcher_b = None
        try:
            observation_a = None
            if not no_baseline:
                events.append({"type": "status", "text": f"{target.id}: baseline lane…"})
                entry_a, observation_a = probe(fetcher_a, target.url, plan.timeout,
                                               "A", plan.trust_source)
                events.append({"type": "log", "entry": entry_a})
                pause()

            proxy = plan.endpoint.acquire(index)
            fetcher_b = make_fetcher(plan.protocol, proxy, plan.trust.verify)
            events.append({"type": "status",
                           "text": f"{target.id}: BlankTrail lane via {proxy} — the solver "
                                   f"can take tens of seconds…"})
            entry_b, observation_b = probe(fetcher_b, target.url, plan.timeout, "B",
                                           plan.trust_source)
            events.append({"type": "log", "entry": entry_b})
            decision = verdict(observation_a, observation_b, no_baseline=no_baseline)
        except Exception as exc:  # noqa: BLE001
            decision = {"verdict": "ERROR", "why": f"{type(exc).__name__}: {exc}"}
        finally:
            if fetcher_b is not None:
                try:
                    fetcher_b.close()
                except Exception:  # noqa: BLE001
                    pass
                plan.endpoint.release(index)

        events.append({"type": "result", "n": index + 1, "id": target.id,
                       "url": target.url, "verdict": decision["verdict"],
                       "why": decision["why"], "no_baseline": no_baseline,
                       "a": _brief(entry_a), "b": _brief(entry_b)})
        pause()
        return events

    fetcher_a = fetcher_b = None
    executor: ThreadPoolExecutor | None = None
    try:
        # Preflight before the first request: one explicit failure beats N silent
        # per-target errors.
        if not no_baseline and plan.lane_a_proxy:
            error = tcp_reachable(plan.lane_a_proxy)
            if error:
                yield {"type": "error", "text": f"run cancelled — baseline lane: {error}"}
                yield {"type": "done"}
                return
        error = plan.endpoint.preflight()
        if error:
            yield {"type": "error", "text": f"run cancelled — {error}"}
            yield {"type": "done"}
            return

        described = plan.endpoint.describe()
        yield {"type": "meta", "targets": len(plan.targets),
               "lane_a": plan.lane_a_mode,
               "lane_a_proxy": plan.lane_a_proxy or "—",
               "lane_b": described,
               "protocol": "HTTP/2 (httpx)" if plan.protocol == "h2" else "HTTP/1.1 (requests)",
               "tls": plan.trust.label,
               "timeout": plan.timeout,
               "pacing": f"{plan.delay_min:.1f}–{plan.delay_max:.1f}s",
               "workers": plan.workers,
               "warnings": plan.warnings + list(getattr(plan.endpoint, "warnings", [])),
               "started": time.strftime("%H:%M:%S")}

        fetcher_a = None if no_baseline else make_fetcher(plan.protocol, plan.lane_a_proxy,
                                                          True)

        if plan.workers <= 1:
            # Deliberately NOT calling process_target() here: this is the
            # exact code this tool has always run for a single-threaded
            # run, unchanged, so that workers == 1 is provably identical to
            # before — not merely equivalent after a refactor. The "else"
            # branch below duplicates this per-target logic instead of
            # sharing it, for that same reason.
            for index, target in enumerate(plan.targets):
                yield {"type": "target", "n": index + 1, "total": len(plan.targets),
                       "id": target.id, "url": target.url}
                entry_a = entry_b = None
                try:
                    observation_a = None
                    if not no_baseline:
                        yield {"type": "status",
                               "text": f"{target.id}: baseline lane…"}
                        entry_a, observation_a = probe(fetcher_a, target.url, plan.timeout,
                                                      "A", plan.trust_source)
                        stats["req"] += 1
                        yield {"type": "log", "entry": entry_a}
                        pause()

                    proxy = plan.endpoint.acquire(index)
                    fetcher_b = make_fetcher(plan.protocol, proxy, plan.trust.verify)
                    yield {"type": "status",
                           "text": f"{target.id}: BlankTrail lane via {proxy} — the solver can "
                                   f"take tens of seconds…"}
                    entry_b, observation_b = probe(fetcher_b, target.url, plan.timeout, "B",
                                                   plan.trust_source)
                    stats["req"] += 1
                    fetcher_b.close()
                    fetcher_b = None
                    plan.endpoint.release(index)
                    yield {"type": "log", "entry": entry_b}
                    decision = verdict(observation_a, observation_b, no_baseline=no_baseline)
                except Exception as exc:  # noqa: BLE001
                    decision = {"verdict": "ERROR", "why": f"{type(exc).__name__}: {exc}"}

                stats["done"] += 1
                stats[STAT_KEY[decision["verdict"]]] += 1
                yield {"type": "result", "n": index + 1, "id": target.id, "url": target.url,
                       "verdict": decision["verdict"], "why": decision["why"],
                       "no_baseline": no_baseline,
                       "a": _brief(entry_a), "b": _brief(entry_b)}
                yield stats_event()
                pause()
        else:
            # Targets run concurrently, but each one's events are collected
            # into a list by process_target() (in a worker thread) and only
            # handed to this generator — the single writer of the stream —
            # once that target is fully done. A target that finishes first
            # is emitted first; targets may complete in any order; nothing
            # from one target's block can land inside another's, because
            # nothing of a block is yielded until the whole block is in
            # hand. Stats are folded in here, in this thread only, right as
            # each block is about to be emitted — not inside the worker
            # threads — so there is exactly one writer of `stats` and no
            # counter update can be lost to a race.
            executor = ThreadPoolExecutor(max_workers=plan.workers)
            futures = [executor.submit(process_target, index, target)
                      for index, target in enumerate(plan.targets)]
            for future in as_completed(futures):
                events = future.result()
                stats["req"] += sum(1 for event in events if event["type"] == "log")
                result_event = next(event for event in events if event["type"] == "result")
                stats["done"] += 1
                stats[STAT_KEY[result_event["verdict"]]] += 1
                for event in events:
                    yield event
                yield stats_event()

        yield {"type": "status", "text": "Done."}
        yield stats_event()
        yield {"type": "done"}
    except GeneratorExit:
        # The browser tab closed. The `finally` below shuts the pool down
        # and closes the port(s) we opened, exactly as it does on every
        # other exit path — see the comment there.
        raise
    except Exception as exc:  # noqa: BLE001
        yield {"type": "error", "text": f"{type(exc).__name__}: {exc}"}
        yield {"type": "done"}
    finally:
        if executor is not None:
            # cancel_futures=True (3.9+) drops every target that has not
            # started yet instead of draining the whole queue. Plain
            # shutdown(wait=True) — or just letting the executor's own
            # context-manager exit run — would let ALL of them run to
            # completion first, which is exactly the "still grinding away
            # after the tab closed" behaviour this is meant to avoid. What
            # IS already running is bounded by plan.workers and by each
            # request's timeout, so this can still take a moment — Python
            # has no way to forcibly interrupt a running thread — but that
            # moment is bounded by the in-flight batch, not by how many
            # targets were left in the list.
            executor.shutdown(wait=True, cancel_futures=True)
        for fetcher in (fetcher_a, fetcher_b):
            if fetcher is not None:
                try:
                    fetcher.close()
                except Exception:  # noqa: BLE001
                    pass
        try:
            plan.endpoint.close()
        finally:
            plan.trust.close()


def _brief(entry: dict | None) -> dict:
    """Short per-lane summary for the verdict row; the raw dump stays in the log."""
    if not entry:
        return {"status": None, "state": "error", "reason": "lane did not run",
                "ms": None, "proto": None, "vendor": "", "signals": {}, "kind": None}
    return {"status": entry["status"], "state": entry["state"], "reason": entry["reason"],
            "ms": entry["ms"], "proto": entry["proto"], "vendor": entry.get("vendor", ""),
            "signals": entry["signals"], "kind": entry.get("kind")}


def execute(config: Mapping) -> Iterator[dict]:
    """The single entry point for the web layer."""
    plan, errors = build_run(config)
    if errors or plan is None:
        yield {"type": "error", "text": "; ".join(errors) or "invalid configuration"}
        yield {"type": "done"}
        return
    yield from run(plan)
