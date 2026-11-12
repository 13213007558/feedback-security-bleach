"""Reusable, thread-safe cleaning entry point built on top of Cleaner.

:class:`bleach.sanitizer.Cleaner` is not thread-safe because the html5lib
parser and tokenizer carry mutable state for the whole lifetime of the
cleaner.  A service that wants to share the *configuration* of a cleaner
between requests therefore has to construct a new ``Cleaner`` for every
request, which repeats the parser/serializer setup on every call.

:class:`CleanerPool` keeps a bounded pool of stateful :class:`Cleaner`
workers.  Configuration is frozen (copied into immutable containers) once,
when the pool is constructed; mutating the caller's original ``tags``,
``attributes`` or ``protocols`` objects afterwards has no effect on the
pool.  Every :meth:`CleanerPool.clean` call checks out one worker for its
exclusive use, so the parser, tokenizer and tree of one request are never
visible to another thread or to a re-entrant clean call made from inside an
attribute callback.

Workers whose cleaning raised are discarded rather than returned to the
pool, so a later caller can never observe a half-finished document left in
the parser of a previous request.
"""

import threading
import warnings

from bleach.sanitizer import (
    ALLOWED_ATTRIBUTES,
    ALLOWED_PROTOCOLS,
    ALLOWED_TAGS,
    Cleaner,
    NoCssSanitizerWarning,
)

_UNSET = object()


def _freeze_tags(tags):
    """Returns an immutable copy of the allowed-tags collection."""
    if tags is None:
        return None
    return frozenset(tags)


def _freeze_protocols(protocols):
    """Returns an immutable copy of the allowed-protocols collection."""
    return frozenset(protocols)


def _freeze_attributes(attributes):
    """Returns an immutable copy of the attributes argument.

    The attributes argument may be a callable, a list or a dict whose values
    are lists/tuples or callables.  Containers are copied into immutable
    equivalents so that later mutation of the caller's objects cannot change
    pool behavior mid-request.  Callables are kept by reference--they are
    configuration supplied by the caller and the pool cannot copy code.
    """
    if callable(attributes):
        return attributes

    if isinstance(attributes, dict):
        frozen = {}
        for tag, value in attributes.items():
            if callable(value):
                frozen[tag] = value
            else:
                frozen[tag] = tuple(value)
        return frozen

    if isinstance(attributes, list):
        return tuple(attributes)

    raise ValueError("attributes needs to be a callable, a list or a dict")


def _freeze_filters(filters):
    """Returns an immutable copy of the filter-class list."""
    return tuple(filters or [])


#: Thread-local mapping of pool -> checked-out worker for the running thread.
#: A single global registry (rather than one per pool) is required so a
#: re-entrant clean call that enters a different pool from the outer call is
#: still recognized as nested.
_thread_state = threading.local()


def _checked_out_workers():
    workers = getattr(_thread_state, "workers", None)
    if workers is None:
        workers = {}
        _thread_state.workers = workers
    return workers


class CleanerPool:
    """A bounded pool of :class:`Cleaner` workers sharing frozen config.

    Construct one pool per configuration and share it across threads::

        from bleach.pool import CleanerPool

        pool = CleanerPool(tags={"p", "a"}, attributes={"a": ["href"]})
        sanitized = pool.clean(yucky_text)

    Thread-safety and re-entrancy:

    * The pool itself is safe to call from multiple threads concurrently.
      Each :meth:`clean` call gets exclusive ownership of a worker and its
      html5lib parser/tokenizer/tree for the duration of the call.
    * If an attribute callback (or filter) calls :meth:`clean` again--on this
      pool or any other pool--while an outer call on the same thread is still
      running, the nested call cannot borrow a worker whose parser is already
      inside the outer document.  A throwaway worker is built for the nested
      call and discarded when it finishes, so re-entrant calls never share
      parser state.
    * When cleaning raises, the worker is discarded instead of being
      recycled.  Subsequent calls always start from a freshly built parser
      and cannot see residue from the failed document.

    Configuration is frozen at construction time.  Mutating the lists, sets
    or dicts passed to the constructor after the pool exists does not affect
    any worker; build a new pool to change configuration.

    .. Warning::

       A ``css_sanitizer`` instance and any callables supplied as
       configuration are shared between workers and therefore must themselves
       be safe to use from multiple threads.
    """

    def __init__(
        self,
        tags=_UNSET,
        attributes=_UNSET,
        protocols=_UNSET,
        strip=False,
        strip_comments=True,
        filters=None,
        css_sanitizer=None,
        max_workers=8,
    ):
        """Initializes a CleanerPool

        :arg set tags: set of allowed tags; defaults to
            ``bleach.sanitizer.ALLOWED_TAGS``
        :arg attributes: allowed attributes; can be a callable, list or dict;
            defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``
        :arg set protocols: set of allowed protocols for links; defaults to
            ``bleach.sanitizer.ALLOWED_PROTOCOLS``
        :arg bool strip: whether or not to strip disallowed elements
        :arg bool strip_comments: whether or not to strip HTML comments
        :arg list filters: list of html5lib Filter classes to pass streamed
            content through
        :arg css_sanitizer: instance with a ``sanitize_css`` method; defaults
            to None
        :arg int max_workers: maximum number of Cleaner workers kept alive by
            the pool; must be at least 1.  When all workers are busy further
            calls block until one is returned.
        """
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")

        # Resolve defaults and freeze every mutable container here, while we
        # are still single-threaded, so the timing of the snapshot is
        # unambiguous: nothing the caller does afterwards can reach a worker.
        frozen_tags = ALLOWED_TAGS if tags is _UNSET else tags
        frozen_attributes = (
            ALLOWED_ATTRIBUTES if attributes is _UNSET else attributes
        )
        frozen_protocols = (
            ALLOWED_PROTOCOLS if protocols is _UNSET else protocols
        )

        # Build a throwaway template once so that construction-time warnings
        # (for example NoCssSanitizerWarning) and validation surface at pool
        # creation rather than on the first request.  Warnings are left
        # enabled here so they fire exactly once for the pool.
        Cleaner(
            tags=frozen_tags,
            attributes=frozen_attributes,
            protocols=frozen_protocols,
            strip=strip,
            strip_comments=strip_comments,
            filters=filters,
            css_sanitizer=css_sanitizer,
        )

        self.tags = _freeze_tags(frozen_tags)
        self.attributes = _freeze_attributes(frozen_attributes)
        self.protocols = _freeze_protocols(frozen_protocols)
        self.strip = strip
        self.strip_comments = strip_comments
        self.filters = _freeze_filters(filters)
        self.css_sanitizer = css_sanitizer
        self.max_workers = max_workers

        # Bounded capacity: at most max_workers live, pooled workers.  RLock
        # because checkout holds this lock while _build_worker re-enters it to
        # update the build counter.
        self._permits = threading.BoundedSemaphore(max_workers)
        self._idle = []
        self._lock = threading.RLock()
        self._workers_built = 0
        self._workers_discarded = 0

        # Eagerly build one worker so construction-time errors in the frozen
        # configuration surface at pool creation rather than on the first
        # request.  The NoCssSanitizerWarning was already emitted above when
        # relevant, so suppress it for the pooled workers.
        worker = self._build_worker()
        self._idle.append(worker)

    def _worker_attributes(self):
        """Returns the frozen attributes in a shape Cleaner accepts.

        The pool keeps an immutable snapshot (tuple / dict of tuples), but
        ``Cleaner.attribute_filter_factory`` only recognizes lists--not
        tuples--for the list form, so hand each worker a fresh list copy built
        from the frozen data.  Callables pass through unchanged.
        """
        attributes = self.attributes
        if isinstance(attributes, tuple):
            return list(attributes)
        if isinstance(attributes, dict):
            return {
                tag: list(value) if isinstance(value, tuple) else value
                for tag, value in attributes.items()
            }
        return attributes

    def _build_worker(self):
        """Builds a new stateful Cleaner from the frozen configuration."""
        with warnings.catch_warnings():
            # The warning was already emitted, when relevant, at pool
            # construction; do not repeat it for every additional worker.
            warnings.simplefilter("ignore", NoCssSanitizerWarning)
            worker = Cleaner(
                tags=self.tags,
                attributes=self._worker_attributes(),
                protocols=self.protocols,
                strip=self.strip,
                strip_comments=self.strip_comments,
                filters=list(self.filters),
                css_sanitizer=self.css_sanitizer,
            )
        # This runs both under the pool lock (normal checkout) and outside it
        # (re-entrant throwaway workers), so the counter needs its own lock.
        with self._lock:
            self._workers_built += 1
        return worker

    def _discard(self):
        """Records that a worker was dropped instead of recycled."""
        with self._lock:
            self._workers_discarded += 1

    def stats(self):
        """Returns pool counters, mainly useful for tests and diagnostics.

        :returns: dict with ``max_workers``, ``idle``, ``workers_built`` and
            ``workers_discarded``
        """
        with self._lock:
            return {
                "max_workers": self.max_workers,
                "idle": len(self._idle),
                "workers_built": self._workers_built,
                "workers_discarded": self._workers_discarded,
            }

    def clean(self, text):
        """Cleans text and returns sanitized result as unicode

        Behaves identically to :meth:`bleach.sanitizer.Cleaner.clean` with
        the pool's frozen configuration, but the parser used for this call is
        exclusive to the call and is never shared with another thread or a
        re-entrant invocation.

        :arg str text: text to be cleaned
        :returns: sanitized text as unicode
        :raises TypeError: if ``text`` is not a text type
        """
        # Validate before checking out a worker.  This error happens before the
        # parser is touched, so no parser state can be affected and a worker
        # must not be discarded for what is purely an input-validation error.
        if not isinstance(text, str):
            message = (
                f"argument cannot be of {text.__class__.__name__!r} type, "
                + "must be of text type"
            )
            raise TypeError(message)

        if not text:
            return ""

        owned = _checked_out_workers()
        if owned:
            # Re-entrant call: this thread is already inside an outer clean
            # (on this pool or another one).  Every worker currently owned by
            # the thread has a parser positioned inside the outer document, so
            # none of them may be reused.  Build a throwaway worker from this
            # pool's frozen config and discard it afterwards; it is not counted
            # against pool capacity and cannot return a contaminated parser to
            # any pool's idle list.
            nested = self._build_worker()
            try:
                return nested.clean(text)
            finally:
                self._discard()

        self._permits.acquire()
        worker = None
        try:
            with self._lock:
                if self._idle:
                    worker = self._idle.pop()
                else:
                    worker = self._build_worker()
            owned[self] = worker
            try:
                return worker.clean(text)
            except BaseException:
                # The parser may hold tokens/tree nodes from the failed
                # document.  Drop the worker so the residue can never reach a
                # later call; the permit is released in finally either way.
                self._discard()
                worker = None
                raise
        finally:
            owned.pop(self, None)
            if worker is not None:
                with self._lock:
                    self._idle.append(worker)
            self._permits.release()
