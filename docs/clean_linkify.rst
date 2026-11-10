.. _clean-linkify-chapter:
.. highlight:: python

==========================================
Cleaning and linkifying in one safe pass
==========================================

Sites that accept comments commonly want to do two things to each comment:

1. clean it so disallowed markup cannot reach the page, and
2. turn the URLs and email addresses in it into links, possibly adjusting
   each link with callbacks that change ``href``, ``target`` or the link text.

:py:func:`bleach.clean_linkify` and the :py:class:`bleach.clean_linkifier.CleanLinker`
class do both in a single parse pass while keeping a fixed, auditable stage
ordering.

The fragment is parsed once and streamed through three filters:

1. **clean** -- ``BleachSanitizerFilter`` applies the tag, attribute and
   protocol policy to the raw fragment,
2. **linkify** -- ``LinkifyFilter`` creates new links and runs every callback,
   once per link, over new and existing links,
3. **final clean** -- ``BleachSanitizerFilter`` runs the *same* policy over the
   callback output.

That third stage is the point of this entry point. Anything a callback adds or
changes is re-validated before it is serialized, so a callback cannot smuggle a
disallowed protocol or attribute into the result.

.. autofunction:: bleach.clean_linkify

.. autoclass:: bleach.clean_linkifier.CleanLinker
   :members:


Inputs, outputs and callback contract
=====================================

Each stage consumes and emits an html5lib token stream, so the fragment is only
parsed once:

* the input is a single HTML fragment as ``str`` (a ``TypeError`` is raised for
  anything else and the empty string returns ``""``);
* the first clean stage only passes allowed tags/attributes through;
* the linkify stage sees the already-cleaned markup and invokes each callback
  exactly once per link -- once for a newly created URL or ``mailto:`` link and
  once for an ``<a>`` tag that was already present;
* the final clean stage validates the attributes the callbacks produced;
* the output is the serialized, safe, linkified fragment as ``str``.

Existing links, newly recognized URLs and email addresses all go through the
same callbacks and the same final checks.

If a callback returns ``None`` the link is dropped and its inner text is
restored as plain text. Because linkification has already finished when the
final clean stage runs, that restored text is not matched and linked a second
time.

Link text a callback returns through the ``_text`` key is emitted as character
data. Markup in it is escaped rather than interpreted as HTML, and existing
entities are not double-escaped.


Example 1 -- the combined entry point guarantees the final output
==================================================================

This is the recommended shape for comment rendering. The final clean stage is
built in, so the callback is free to rewrite attributes without becoming part
of your trust boundary.

Note that ``target`` and ``rel`` have to be in the attribute allow-list, or the
final clean stage removes them -- that removal is the safety check working.

.. doctest::

   >>> import bleach
   >>> from bleach.callbacks import nofollow, target_blank

   >>> attrs = {'a': ['href', 'title', 'target', 'rel']}
   >>> bleach.clean_linkify(
   ...     'see http://example.com <script>bad()</script>',
   ...     attributes=attrs,
   ...     callbacks=[nofollow, target_blank],
   ... )
   'see <a href="http://example.com" rel="nofollow" target="_blank">http://example.com</a> &lt;script&gt;bad()&lt;/script&gt;'

A callback that points a link at a disallowed protocol is neutralized by the
final clean stage:

.. doctest::

   >>> def evil_href(attrs, new=False):
   ...     attrs[(None, 'href')] = 'javascript:alert(1)'
   ...     return attrs
   ...
   >>> bleach.clean_linkify('http://example.com', callbacks=[evil_href])
   '<a>http://example.com</a>'

And a callback that returns ``None`` restores the text without creating a link:

.. doctest::

   >>> def drop_new(attrs, new=False):
   ...     return None if new else attrs
   ...
   >>> bleach.clean_linkify('see http://example.com end', callbacks=[drop_new])
   'see http://example.com end'


Example 2 -- composing the filters yourself (different ordering, no final check)
=================================================================================

The lower-level building blocks are still available. A
:py:class:`bleach.sanitizer.Cleaner` accepts filter classes, so you can place
:py:class:`bleach.linkifier.LinkifyFilter` in its filter chain. This parses the
fragment once as well, but the ordering is just clean -> linkify: there is no
sanitizer running *after* the callbacks.

.. doctest::

   >>> from functools import partial
   >>> from bleach.sanitizer import Cleaner
   >>> from bleach.linkifier import LinkifyFilter

   >>> cleaner = Cleaner(filters=[LinkifyFilter])
   >>> cleaner.clean('see http://example.com <script>bad()</script>')
   'see <a href="http://example.com" rel="nofollow">http://example.com</a> &lt;script&gt;bad()&lt;/script&gt;'

That is convenient, but any callback you add here writes attributes straight
into the output. With no final clean stage, an unsafe ``href`` is not caught:

.. doctest::

   >>> cleaner = Cleaner(filters=[partial(LinkifyFilter, callbacks=[evil_href])])
   >>> cleaner.clean('http://example.com')
   '<a href="javascript:alert(1)">http://example.com</a>'

So the responsibility split is:

* :py:func:`bleach.clean_linkify` / :py:class:`bleach.clean_linkifier.CleanLinker`
  guarantee the final output -- the closing clean pass always runs after the
  callbacks;
* a hand-wired ``Cleaner(filters=[LinkifyFilter])`` (or any other filter
  composition) leaves the lower-level filters under the caller's control, and
  the caller is responsible for validating what those filters produce.

Prefer the combined entry point unless you specifically need a custom filter
ordering.
