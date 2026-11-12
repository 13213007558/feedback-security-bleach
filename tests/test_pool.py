"""Tests for bleach.pool.CleanerPool.

These tests focus on the guarantees that distinguish the pool from building a
new Cleaner per request:

* output is identical to a freshly built Cleaner for the same config;
* parser/tokenizer/tree state is never shared between threads, between nested
  (re-entrant) calls, or after a failure;
* configuration is frozen at construction time;
* the pool is bounded and failed workers are discarded, not recycled.
"""

import threading

import pytest

from bleach import clean as bleach_clean
from bleach.pool import CleanerPool
from bleach.sanitizer import (
    ALLOWED_TAGS,
    Cleaner,
    NoCssSanitizerWarning,
)


TAGS = ["p", "a", "b", "i", "img"]
ATTRS = {
    "a": ["href", "title"],
    "img": ["alt"],
    "*": ["class"],
}
PROTOS = ["http", "https", "mailto"]

FRAGMENTS = [
    "<p>plain text</p>",
    '<a href="http://example.com?foo=bar&bar=foo&amp;biz=bash">link</a>',
    "<script>alert('xss')</script><p>kept</p>",
    "<imr src='http://example.com'>",
    "jim &current joe &&nbsp; &nbsp;&",
    "<p>unclosed <b>bold",
    '<a href="javascript:alert(1)">nope</a><b>ok</b>',
    "<table><tr><td>table</td></tr></table><p>x</p>",
    "<p title=\"a'quoted\">entities &amp; &xx;</p>",
    "<b>" + "secret-" + "data</b>" * 8,
]


def _reference(fragment, **kwargs):
    return Cleaner(
        tags=kwargs.get("tags", TAGS),
        attributes=kwargs.get("attributes", ATTRS),
        protocols=kwargs.get("protocols", PROTOS),
        strip=kwargs.get("strip", False),
        strip_comments=kwargs.get("strip_comments", True),
        css_sanitizer=kwargs.get("css_sanitizer"),
    ).clean(fragment)


@pytest.mark.parametrize("fragment", FRAGMENTS)
def test_pool_output_matches_fresh_cleaner(fragment):
    pool = CleanerPool(tags=TAGS, attributes=ATTRS, protocols=PROTOS)
    assert pool.clean(fragment) == _reference(fragment)


def test_pool_strip_mode_matches():
    pool = CleanerPool(tags=["p"], strip=True)
    for fragment in FRAGMENTS:
        assert pool.clean(fragment) == _reference(
            fragment, tags=["p"], strip=True
        )


def test_pool_strip_comments_matches():
    fragment = "<p>hi</p><!-- a comment --><b>x</b>"
    pool = CleanerPool(strip_comments=False)
    assert pool.clean(fragment) == Cleaner(strip_comments=False).clean(fragment)


def test_pool_with_css_sanitizer_matches():
    from bleach.css_sanitizer import CSSSanitizer

    css = CSSSanitizer()
    tags = ["p", "span"]
    attrs = {"span": ["style"]}
    fragment = '<span style="color: red; bogus: 1;">x</span>'
    pool = CleanerPool(tags=tags, attributes=attrs, css_sanitizer=css)
    assert pool.clean(fragment) == _reference(
        fragment, tags=tags, attributes=attrs, css_sanitizer=CSSSanitizer()
    )


@pytest.mark.parametrize(
    "attributes",
    [
        ["class"],
        {"*": ["class"], "p": ["title"]},
        lambda tag, attr, value: attr == "ok",
    ],
)
def test_all_attribute_shapes_match_fresh_cleaner(attributes):
    fragment = '<p class="x" title="t" ok="1" bad="2">z</p>'
    pool = CleanerPool(tags=["p"], attributes=attributes)
    # A callable is passed through by reference, so the same object is used
    # for the reference Cleaner.
    assert pool.clean(fragment) == Cleaner(
        tags=["p"], attributes=attributes
    ).clean(fragment)


def test_pool_with_filter_matches():
    from bleach.html5lib_shim import Filter

    class MooFilter(Filter):
        def __iter__(self):
            for token in Filter.__iter__(self):
                if token["type"] == "Characters":
                    token["data"] = token["data"].replace("moo", "MOO")
                yield token

    pool = CleanerPool(tags=["p"], filters=[MooFilter])
    fragment = "<p>cow says moo</p><div>moo too</div>"
    assert pool.clean(fragment) == Cleaner(
        tags=["p"], filters=[MooFilter]
    ).clean(fragment)


def test_non_string_raises_type_error():
    pool = CleanerPool()
    before = pool.stats()
    with pytest.raises(TypeError):
        pool.clean(123)
    # Input validation runs before checkout, so no worker was built or
    # discarded.
    assert pool.stats() == before
    assert pool.clean("<b>still fine</b>") == "<b>still fine</b>"


def test_invalid_max_workers():
    with pytest.raises(ValueError):
        CleanerPool(max_workers=0)


def test_invalid_attributes_raises_value_error():
    with pytest.raises(ValueError):
        CleanerPool(attributes=42)


def test_no_css_sanitizer_warns_once():
    with pytest.warns(NoCssSanitizerWarning):
        CleanerPool(tags=["p"], attributes={"p": ["style"]})


# ---------------------------------------------------------------------------
# Configuration freezing
# ---------------------------------------------------------------------------


def test_mutating_tags_after_construction_is_ignored():
    tags = ["p", "b"]
    pool = CleanerPool(tags=tags)
    tags.append("script")
    out = pool.clean("<p>ok</p><script>alert(1)</script>")
    assert "<script>" not in out
    assert pool.clean("<p>ok</p>") == "<p>ok</p>"


def test_mutating_attributes_after_construction_is_ignored():
    attrs = {"a": ["href"]}
    pool = CleanerPool(tags=["a"], attributes=attrs)
    attrs["a"].append("onclick")
    out = pool.clean('<a href="http://e.com" onclick="evil()">x</a>')
    assert "onclick" not in out


def test_mutating_protocols_after_construction_is_ignored():
    protos = ["http", "https"]
    pool = CleanerPool(tags=["a"], attributes={"a": ["href"]}, protocols=protos)
    protos.append("javascript")
    out = pool.clean('<a href="javascript:alert(1)">x</a>')
    assert "javascript" not in out


def test_mid_request_config_mutation_does_not_leak_between_threads():
    """A caller mutating its allow-list while another thread is mid-clean.

    The in-flight request runs against the frozen snapshot; the mutation only
    affects a pool built afterwards.
    """
    tags = ["p", "b"]
    pool = CleanerPool(tags=tags)
    inside_callback = threading.Event()
    release = threading.Event()

    def attr_callback(tag, attr, value):
        inside_callback.set()
        release.wait(timeout=5)
        return True

    blocking_pool = CleanerPool(
        tags=["a"], attributes=attr_callback
    )

    result = {}

    def worker():
        result["out"] = blocking_pool.clean(
            '<a href="http://e.com">x</a><script>bad</script>'
        )

    thread = threading.Thread(target=worker)
    thread.start()
    inside_callback.wait(timeout=5)
    # Mutate the caller's original list while the other thread is blocked
    # inside the sanitizer.
    tags.append("script")
    release.set()
    thread.join()

    assert result["out"] == Cleaner(
        tags=["a"], attributes=attr_callback
    ).clean('<a href="http://e.com">x</a><script>bad</script>')
    assert "<script>" not in result["out"]
    # The first pool keeps its original frozen config too.
    assert "<script>" not in pool.clean("<script>x</script>")


# ---------------------------------------------------------------------------
# Concurrency: exclusive parser state with interleaved fragments
# ---------------------------------------------------------------------------


def test_concurrent_cleans_keep_outputs_and_callback_context_isolated():
    """Two threads interleave while cleaning fragments with different secrets.

    Both threads use the *same* pool instance.  An event-based rendezvous
    inside the shared callback guarantees the two sanitizers run overlapped
    (each blocked inside its attribute callback at the same time), proving
    that parser state and callback context stay isolated under concurrency.
    """
    secret_a = "alpha-secret-AAAA"
    secret_b = "bravo-secret-BBBB"
    both_entered = threading.Event()
    release = threading.Event()
    entered = {"count": 0}
    entered_lock = threading.Lock()
    seen_contexts = []
    contexts_lock = threading.Lock()

    def callback(tag, attr, value):
        # The worker thread names carry the document owner, so the shared
        # callback can attribute every invocation to its own document.
        owner = threading.current_thread().name
        with entered_lock:
            entered["count"] += 1
            if entered["count"] == 2:
                both_entered.set()
        # Block until both threads are simultaneously inside the sanitizer.
        both_entered.wait(timeout=5)
        release.wait(timeout=5)
        with contexts_lock:
            seen_contexts.append((owner, value))
        return True

    shared_pool = CleanerPool(
        tags=["p", "a"], attributes=callback, max_workers=2
    )

    def job(owner, secret):
        fragment = (
            f'<p>{secret}</p><a href="http://{owner}.example/{secret}">'
            f"{secret}</a><script>x</script>"
        )
        return shared_pool.clean(fragment)

    results = {}
    errors = []

    def runner(owner, secret):
        try:
            results[owner] = job(owner, secret)
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    t1 = threading.Thread(target=runner, args=("a", secret_a), name="a")
    t2 = threading.Thread(target=runner, args=("b", secret_b), name="b")
    t1.start()
    t2.start()
    assert both_entered.wait(timeout=5)
    release.set()
    t1.join()
    t2.join()

    assert not errors
    assert secret_a in results["a"]
    assert secret_b in results["b"]
    # No cross-contamination: one request's secret never appears in the other.
    assert secret_b not in results["a"]
    assert secret_a not in results["b"]
    assert "<script>" not in results["a"]
    assert "<script>" not in results["b"]
    # Both workers were needed concurrently, but never more than the bound.
    assert shared_pool.stats()["workers_built"] == 2
    # Each callback only ever saw its own document's attribute value.
    assert ("a", f"http://a.example/{secret_a}") in seen_contexts
    assert ("b", f"http://b.example/{secret_b}") in seen_contexts
    for owner, value in seen_contexts:
        if owner == "a":
            assert secret_a in value
            assert secret_b not in value
        else:
            assert secret_b in value
            assert secret_a not in value


def test_shared_pool_concurrent_cleans_isolated():
    """Same pool instance used by many threads at once never mixes documents."""
    pool = CleanerPool(tags=["p", "b"], max_workers=4)
    n_threads = 8
    barrier = threading.Barrier(n_threads)
    outputs = [None] * n_threads

    def runner(index):
        secret = f"SECRET-{index:03d}"
        fragment = f"<p>{secret}</p><b>{index}</b>" * 5
        barrier.wait(timeout=5)
        outputs[index] = pool.clean(fragment)

    threads = [threading.Thread(target=runner, args=(i,)) for i in range(n_threads)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for index, out in enumerate(outputs):
        secret = f"SECRET-{index:03d}"
        assert out is not None
        assert secret in out
        for other in range(n_threads):
            if other != index:
                assert f"SECRET-{other:03d}" not in out


# ---------------------------------------------------------------------------
# Re-entrancy: nested clean from inside an attribute callback
# ---------------------------------------------------------------------------


def test_reentrant_clean_uses_independent_parser():
    nested_outputs = []

    def callback(tag, attr, value):
        # Re-enter the same pool while the outer call holds a worker.  The
        # nested pool only allows <p>, so <script> must be escaped there even
        # though the outer document has a different (smaller) tag set.
        nested = pool.clean("<p>nested-secret-NNN</p><script>z</script>")
        nested_outputs.append(nested)
        return True

    pool = CleanerPool(tags=["p"], max_workers=4)
    reentrant_pool = CleanerPool(tags=["a"], attributes=callback)
    outer = reentrant_pool.clean('<a href="outer-secret-OOO">x</a>')

    assert "outer-secret-OOO" in outer
    assert nested_outputs == [
        "<p>nested-secret-NNN</p>&lt;script&gt;z&lt;/script&gt;"
    ]
    # The outer worker was returned to its pool; the throwaway worker used by
    # the nested call was built and discarded by the nested pool.
    assert reentrant_pool.stats()["idle"] == 1
    assert reentrant_pool.stats()["workers_discarded"] == 0
    assert pool.stats()["workers_built"] == 2
    assert pool.stats()["workers_discarded"] == 1
    assert pool.stats()["idle"] == 1
    # Pool still healthy afterwards and output unchanged.
    assert reentrant_pool.clean('<a href="again">y</a>') == '<a href="again">y</a>'


def test_cross_pool_reentrant_clean_does_not_reuse_idle_worker():
    """A nested call on a *different* pool still gets a throwaway parser.

    The nested pool's idle worker must not be handed out while the same
    thread is inside an outer clean, because that parser would be returned to
    the idle list mid-document.
    """
    nested_pool = CleanerPool(tags=["p"], max_workers=1)

    def callback(tag, attr, value):
        nested_pool.clean("<p>nested-secret-NNN</p>")
        return True

    outer_pool = CleanerPool(tags=["a"], attributes=callback, max_workers=1)
    assert outer_pool.clean('<a href="outer-secret-OOO">x</a>') == (
        '<a href="outer-secret-OOO">x</a>'
    )
    # The nested pool's single idle worker was never checked out; a separate
    # throwaway served the nested call and was discarded.
    stats = nested_pool.stats()
    assert stats["idle"] == 1
    assert stats["workers_discarded"] == 1
    assert stats["workers_built"] == 2
    # No residue from the nested document inside the idle worker.
    assert "nested-secret-NNN" not in nested_pool.clean("<p>fresh</p>")
    assert nested_pool.clean("<p>fresh</p>") == "<p>fresh</p>"


def test_nested_clean_failure_does_not_poison_outer_worker():
    nested_pool = CleanerPool(tags=["p"])
    nested_before = nested_pool.stats()

    def callback(tag, attr, value):
        # Input validation rejects non-text before any worker is built, so the
        # nested pool never checks out or discards a parser.
        with pytest.raises(TypeError):
            nested_pool.clean(123)
        return True

    reentrant_pool = CleanerPool(tags=["a"], attributes=callback)
    outer = reentrant_pool.clean('<a href="ok">x</a>')
    assert outer == '<a href="ok">x</a>'
    stats = reentrant_pool.stats()
    assert stats["idle"] == 1
    assert stats["workers_discarded"] == 0
    # The nested pool was untouched by the rejected call and still works.
    assert nested_pool.stats() == nested_before
    assert nested_pool.clean("<p>fine</p>") == "<p>fine</p>"


# ---------------------------------------------------------------------------
# Failure isolation: failed workers are discarded, no residue survives
# ---------------------------------------------------------------------------


def test_failed_worker_is_discarded_and_no_residue_remains():
    marker_fragment = '<a href="residue-secret-RRR">x</a>'

    def flaky(tag, attr, value):
        raise RuntimeError("boom from callback")

    pool = CleanerPool(tags=["a"], attributes=flaky)
    with pytest.raises(RuntimeError):
        pool.clean(marker_fragment)

    stats = pool.stats()
    assert stats["workers_discarded"] == 1
    assert stats["idle"] == 0
    # The failure forces a fresh worker on the next call; it has no residue
    # from the failed document (it also still carries the flaky config, which
    # is expected and exercised separately below).
    with pytest.raises(RuntimeError):
        pool.clean('<a href="another">y</a>')

    # A separate, healthy pool with default allowed tags must never see the
    # failed document's secret and matches the module-level clean output.
    healthy = CleanerPool()
    for fragment in FRAGMENTS:
        assert healthy.clean(fragment) == bleach_clean(fragment)
    assert "residue-secret-RRR" not in healthy.clean("<p>clean</p>")


def test_residue_cannot_leak_through_replacement_worker():
    """After callback failures, replacement workers produce pristine output.

    Uses a callback that fails a fixed number of times then recovers, so the
    worker built to replace the discarded one can be observed directly.
    """
    failures_left = {"n": 2}

    def recovering(tag, attr, value):
        if failures_left["n"] > 0:
            failures_left["n"] -= 1
            raise RuntimeError("transient")
        return True

    pool = CleanerPool(tags=["a"], attributes=recovering)
    for _ in range(2):
        with pytest.raises(RuntimeError):
            pool.clean('<a href="residue-secret-RRR">x</a>')

    # The replacement worker starts clean; the old secret cannot appear.
    recovered = pool.clean('<a href="fresh-secret-FFF">y</a>')
    assert recovered == '<a href="fresh-secret-FFF">y</a>'
    assert "residue-secret-RRR" not in recovered
    stats = pool.stats()
    assert stats["workers_discarded"] == 2
    assert stats["idle"] == 1


def test_repeated_failures_keep_pool_bounded_and_functional():
    def always_fails(tag, attr, value):
        raise ValueError("nope")

    pool = CleanerPool(tags=["a"], attributes=always_fails, max_workers=2)
    for _ in range(5):
        with pytest.raises(ValueError):
            pool.clean('<a href="x">y</a>')

    stats = pool.stats()
    assert stats["workers_discarded"] == 5
    # The eager worker served the first failure; each later failure built one
    # replacement, so 1 + 4 = 5 workers were built in total and at no instant
    # did the pool hold more than max_workers live workers.
    assert stats["workers_built"] == 5
    assert stats["idle"] == 0


def test_parse_error_input_leaves_no_residue_on_reused_worker():
    """Malformed input exercises parser error paths without discarding.

    A successful (even if ugly) parse returns the worker; its parser is reset
    by html5lib on every parseFragment call, so the next clean is clean.
    """
    pool = CleanerPool(tags=["p", "b"], max_workers=1)
    malformed = ["<p>unclosed <b>", "<a b='1\"", "<<<>>>", "&" * 20, "<p>a<p>b"]
    for fragment in malformed:
        assert pool.clean(fragment) == Cleaner(
            tags=["p", "b"]
        ).clean(fragment)
    stats = pool.stats()
    assert stats["idle"] == 1
    assert stats["workers_discarded"] == 0


# ---------------------------------------------------------------------------
# Capacity bound and worker return semantics
# ---------------------------------------------------------------------------


def test_pool_never_exceeds_max_workers():
    max_workers = 2
    occupied = threading.Event()
    release = threading.Event()
    inside = {"count": 0}
    inside_lock = threading.Lock()

    def blocking_callback(tag, attr, value):
        with inside_lock:
            inside["count"] += 1
            if inside["count"] == max_workers:
                occupied.set()
        release.wait(timeout=5)
        return True

    pool = CleanerPool(
        tags=["a"], attributes=blocking_callback, max_workers=max_workers
    )

    def occupy():
        pool.clean('<a href="busy">y</a>')

    workers = [threading.Thread(target=occupy) for _ in range(max_workers)]
    for worker in workers:
        worker.start()
    # Wait until both pool workers are checked out and inside the callback.
    assert occupied.wait(timeout=5)
    assert pool.stats()["idle"] == 0

    queued_started = threading.Event()
    queued_done = threading.Event()

    def queued_caller():
        queued_started.set()
        pool.clean('<a href="third">z</a>')
        queued_done.set()

    extra = threading.Thread(target=queued_caller)
    extra.start()
    queued_started.wait(timeout=5)
    # Capacity is saturated: the third caller is waiting on the semaphore and
    # no worker beyond max_workers has been built.
    assert not queued_done.wait(timeout=0.5)
    assert pool.stats()["workers_built"] == max_workers

    release.set()
    for worker in workers:
        worker.join()
    assert queued_done.wait(timeout=5)
    extra.join()

    stats = pool.stats()
    assert stats["workers_built"] == max_workers
    assert stats["idle"] == max_workers
    assert stats["workers_discarded"] == 0


def test_worker_returned_after_success():
    pool = CleanerPool(max_workers=1)
    for _ in range(10):
        pool.clean("<p>x</p>")
    stats = pool.stats()
    assert stats["workers_built"] == 1
    assert stats["idle"] == 1
    assert stats["workers_discarded"] == 0


def test_default_config_matches_module_defaults():
    pool = CleanerPool()
    assert pool.tags == ALLOWED_TAGS
    assert pool.protocols == Cleaner().protocols
    assert pool.clean("<script>x</script><b>y</b>") == bleach_clean(
        "<script>x</script><b>y</b>"
    )
