"""Single-entry-point pipeline that cleans, linkifies, and then re-checks.

This module ties :class:`bleach.sanitizer.BleachSanitizerFilter` and
:class:`bleach.linkifier.LinkifyFilter` together into one parse pass with an
explicit, fixed ordering:

1. **clean** -- strip/escape disallowed tags and attributes so that linkify
   only ever sees trusted markup,
2. **linkify** -- create new links and run the user callbacks over both new
   and existing links,
3. **final clean** -- run the *same* allow-list and protocol policy over the
   output of the callbacks so a callback that changes ``href`` or adds
   attributes cannot smuggle a disallowed protocol or attribute into the
   result.

The final clean is what makes this entry point safe to use with arbitrary
callbacks.  Composing the lower-level filters yourself (for example with
``Cleaner(filters=[LinkifyFilter])``) does not add that final pass, so the
caller remains responsible for any safety guarantees in that case.
"""

from bleach import html5lib_shim
from bleach.linkifier import (
    DEFAULT_CALLBACKS,
    EMAIL_RE,
    URL_RE,
    LinkifyFilter,
)
from bleach.sanitizer import (
    ALLOWED_ATTRIBUTES,
    ALLOWED_PROTOCOLS,
    ALLOWED_TAGS,
    BleachSanitizerFilter,
)


class CleanLinker:
    """Clean, linkify and then perform a final safety check in one parse pass.

    The fragment is parsed once and streamed through three filters in order::

        BleachSanitizerFilter -> LinkifyFilter -> BleachSanitizerFilter

    The two sanitizer filters share the exact same tag, attribute and protocol
    policy.  The second one is the explicit final check: every attribute a
    linkify callback adds or changes (including ``href``, ``target`` and
    ``rel``) is re-validated against the allow-list and the allowed protocols
    before it is serialized.

    Link text supplied by a callback through the ``_text`` key is emitted as
    character data, so markup in it is escaped rather than parsed as HTML.

    .. Warning::

       This class is not thread-safe--the html parser has internal state.
       Create a separate instance per thread!
    """

    def __init__(
        self,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=False,
        strip_comments=True,
        css_sanitizer=None,
        callbacks=DEFAULT_CALLBACKS,
        skip_tags=None,
        parse_email=False,
        url_re=URL_RE,
        email_re=EMAIL_RE,
    ):
        """Creates a CleanLinker instance.

        :arg set tags: set of allowed tags; defaults to
            ``bleach.sanitizer.ALLOWED_TAGS``

        :arg dict attributes: allowed attributes; can be a callable, list or
            dict; defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``

        :arg set protocols: set of allowed protocols for links; defaults to
            ``bleach.sanitizer.ALLOWED_PROTOCOLS``

        :arg bool strip: whether or not to strip disallowed elements

        :arg bool strip_comments: whether or not to strip HTML comments

        :arg CSSSanitizer css_sanitizer: instance with a "sanitize_css"
            method for sanitizing style attribute values and style text

        :arg list callbacks: list of callbacks to run when adjusting tag
            attributes; defaults to ``bleach.linkifier.DEFAULT_CALLBACKS``

        :arg set skip_tags: set of tags whose contents must not be linkified;
            ``None`` means no tags are skipped

        :arg bool parse_email: whether or not to linkify email addresses

        :arg url_re: url matching regex

        :arg email_re: email matching regex
        """
        self.tags = tags
        self.attributes = attributes
        self.protocols = protocols
        self.strip = strip
        self.strip_comments = strip_comments
        self.css_sanitizer = css_sanitizer
        self.callbacks = callbacks
        self.skip_tags = skip_tags
        self.parse_email = parse_email
        self.url_re = url_re
        self.email_re = email_re

        self.parser = html5lib_shim.BleachHTMLParser(
            tags=self.tags,
            strip=self.strip,
            consume_entities=False,
            namespaceHTMLElements=False,
        )
        self.walker = html5lib_shim.getTreeWalker("etree")
        self.serializer = html5lib_shim.BleachHTMLSerializer(
            quote_attr_values="always",
            omit_optional_tags=False,
            escape_lt_in_attrs=True,
            resolve_entities=False,
            sanitize=False,
            alphabetical_attributes=False,
        )

    def _sanitizer_kwargs(self):
        """Policy shared by the opening and the final sanitizer filters."""
        return {
            "allowed_tags": self.tags,
            "attributes": self.attributes,
            "allowed_protocols": self.protocols,
            "strip_disallowed_tags": self.strip,
            "strip_html_comments": self.strip_comments,
            "css_sanitizer": self.css_sanitizer,
        }

    def clean_linkify(self, text):
        """Clean, linkify and finally re-check ``text``.

        :arg str text: the HTML fragment to process

        :returns: the safe, linkified text as unicode

        :raises TypeError: if ``text`` is not a text type
        """
        if not isinstance(text, str):
            message = (
                f"argument cannot be of {text.__class__.__name__!r} type, "
                + "must be of text type"
            )
            raise TypeError(message)

        if not text:
            return ""

        dom = self.parser.parseFragment(text)
        stream = self.walker(dom)

        # Stage 1: clean the raw fragment first.
        stream = BleachSanitizerFilter(source=stream, **self._sanitizer_kwargs())

        # Stage 2: linkify and run the callbacks exactly once per link.
        stream = LinkifyFilter(
            source=stream,
            callbacks=self.callbacks,
            skip_tags=self.skip_tags,
            parse_email=self.parse_email,
            url_re=self.url_re,
            email_re=self.email_re,
        )

        # Stage 3: explicit final safety check of the callback output.
        stream = BleachSanitizerFilter(source=stream, **self._sanitizer_kwargs())

        return self.serializer.render(stream)


def clean_linkify(
    text,
    tags=ALLOWED_TAGS,
    attributes=ALLOWED_ATTRIBUTES,
    protocols=ALLOWED_PROTOCOLS,
    strip=False,
    strip_comments=True,
    css_sanitizer=None,
    callbacks=DEFAULT_CALLBACKS,
    skip_tags=None,
    parse_email=False,
):
    """Clean an HTML fragment, linkify it, and run a final safety check.

    This is a convenience wrapper around :class:`CleanLinker` for call sites
    that process a single fragment.  It always guarantees the ordering
    clean -> linkify -> final clean, so attributes produced or changed by the
    linkify callbacks are validated against the allow-list and the allowed
    protocols one last time before the result is returned.

    If you are processing many fragments with the same configuration, build a
    :class:`CleanLinker` once and reuse it instead.

    :arg str text: the HTML fragment to process

    :returns: the safe, linkified text as unicode
    """
    linker = CleanLinker(
        tags=tags,
        attributes=attributes,
        protocols=protocols,
        strip=strip,
        strip_comments=strip_comments,
        css_sanitizer=css_sanitizer,
        callbacks=callbacks,
        skip_tags=skip_tags,
        parse_email=parse_email,
    )
    return linker.clean_linkify(text)
