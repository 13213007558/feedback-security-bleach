#!/usr/bin/env python
"""Local micro-benchmark for CleanerPool versus a fresh Cleaner per request.

It measures the two cost buckets separately:

1. **config prep** -- building Cleaner workers (parser, walker, serializer
   setup) without parsing any text;
2. **parse work** -- the actual ``clean`` of a fragment using an already
   prepared worker.

All data is generated in-process; nothing touches the network.  Total runtime
is a few seconds.  Run it directly::

    python scripts/benchmark_pool.py
"""

import gc
import statistics
import time

from bleach.pool import CleanerPool
from bleach.sanitizer import Cleaner


TAGS = ["p", "a", "b", "i", "img"]
ATTRIBUTES = {"a": ["href", "title"], "img": ["alt"], "*": ["class"]}
PROTOCOLS = ["http", "https", "mailto"]

# Synthetic, request-sized fragments with distinct "fake secret" tokens so the
# workload also mirrors the isolation tests.
SMALL_FRAGMENTS = [
    "<p>hello <b>world</b></p>",
    '<a href="https://example.com/secret-{i}?a=1&amp;b=2">secret-{i}</a>',
    "<p>token-{i} &amp; entity &xx; <i>text</i></p>",
    "<div>strip-me-{i}</div><p>keep-{i}</p>",
]
LARGE_FRAGMENT = (
    "<p>secret-{i} <b>bold</b> "
    '<a href="https://example.com/p/{i}?x=1&y=2">link-{i}</a> &amp; end</p> '
) * 25

ITERATIONS = 2000
LARGE_ITERATIONS = 80
REPEATS = 5


def fragments(template, iterations=ITERATIONS):
    return [template.format(i=i) for i in range(iterations)]


def time_it(fn, iterations, repeats=REPEATS):
    samples = []
    gc.collect()
    gc.disable()
    try:
        for _ in range(repeats):
            start = time.perf_counter()
            fn()
            samples.append((time.perf_counter() - start) / iterations * 1e6)
    finally:
        gc.enable()
    return statistics.mean(samples), statistics.stdev(samples)


def bench(label, fragments, iterations):
    print(f"\n=== {label} ({len(fragments[0])} chars/fragment) ===")

    # --- config preparation ----------------------------------------------
    def fresh_cleaner_only():
        for _ in range(iterations):
            Cleaner(tags=TAGS, attributes=ATTRIBUTES, protocols=PROTOCOLS)

    def pool_build_one_worker():
        # What a pool pays the first time a new worker is needed.
        pool = CleanerPool(tags=TAGS, attributes=ATTRIBUTES, protocols=PROTOCOLS)
        for _ in range(iterations):
            pool._build_worker()

    def pool_construction():
        for _ in range(iterations):
            CleanerPool(tags=TAGS, attributes=ATTRIBUTES, protocols=PROTOCOLS)

    # --- parse work ------------------------------------------------------
    shared_cleaner = Cleaner(
        tags=TAGS, attributes=ATTRIBUTES, protocols=PROTOCOLS
    )
    pool = CleanerPool(tags=TAGS, attributes=ATTRIBUTES, protocols=PROTOCOLS)

    def fresh_per_request():
        # The status quo: config prep + parse on every request.
        for fragment in fragments:
            Cleaner(
                tags=TAGS, attributes=ATTRIBUTES, protocols=PROTOCOLS
            ).clean(fragment)

    def pooled():
        for fragment in fragments:
            pool.clean(fragment)

    def reused_single_cleaner():
        # Lower bound for parse cost alone; NOT thread-safe, shown for
        # comparison only.
        for fragment in fragments:
            shared_cleaner.clean(fragment)

    rows = [
        ("config prep: Cleaner() per request", fresh_cleaner_only),
        ("config prep: pool worker build", pool_build_one_worker),
        ("config prep: whole CleanerPool()", pool_construction),
        ("full request: fresh Cleaner + clean", fresh_per_request),
        ("full request: CleanerPool.clean", pooled),
        ("full request: reused single Cleaner (unsafe)", reused_single_cleaner),
    ]
    print(f"{'scenario':45} {'us/call':>10} {'stdev':>8}")
    baseline = None
    for name, fn in rows:
        mean, stdev = time_it(fn, iterations)
        if baseline is None and name.startswith("full request: fresh"):
            baseline = mean
        marker = ""
        if baseline and name.startswith("full request"):
            marker = f"  ({mean / baseline * 100:.0f}% of fresh-per-request)"
        print(f"{name:45} {mean:10.1f} {stdev:8.2f}{marker}")

    # Correctness cross-check: pooled output must equal fresh-Cleaner output.
    for fragment in fragments[:50]:
        assert pool.clean(fragment) == Cleaner(
            tags=TAGS, attributes=ATTRIBUTES, protocols=PROTOCOLS
        ).clean(fragment)
    print("correctness: pooled output equals fresh Cleaner output (checked 50)")


def main():
    small = []
    for i in range(ITERATIONS):
        small.append(SMALL_FRAGMENTS[i % len(SMALL_FRAGMENTS)].format(i=i))
    bench("mixed small fragments", small, ITERATIONS)
    bench(
        "large fragment",
        fragments(LARGE_FRAGMENT, LARGE_ITERATIONS),
        LARGE_ITERATIONS,
    )


if __name__ == "__main__":
    main()
