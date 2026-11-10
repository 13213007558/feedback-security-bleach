from bleach.clean_linkifier import CleanLinker, clean_linkify
from bleach.linkifier import (
    DEFAULT_CALLBACKS,
    Linker,
)
from bleach.sanitizer import (
    ALLOWED_ATTRIBUTES,
    ALLOWED_PROTOCOLS,
    ALLOWED_TAGS,
    Cleaner,
)


# yyyymmdd
__releasedate__ = "20260605"
# x.y.z or x.y.z.dev0 -- semver
__version__ = "6.4.0"


__all__ = ["clean", "clean_linkify", "linkify"]


def clean(
    text,
    tags=ALLOWED_TAGS,
    attributes=ALLOWED_ATTRIBUTES,
    protocols=ALLOWED_PROTOCOLS,
    strip=False,
    strip_comments=True,
    css_sanitizer=None,
):
    """Clean an HTML fragment of malicious content and return it

    This function is a security-focused function whose sole purpose is to
    remove malicious content from a string such that it can be displayed as
    content in a web page.

    This function is not designed to use to transform content to be used in
    non-web-page contexts.

    Example::

        import bleach

        better_text = bleach.clean(yucky_text)


    .. Note::

       If you're cleaning a lot of text and passing the same argument values or
       you want more configurability, consider using a
       :py:class:`bleach.sanitizer.Cleaner` instance.

    :arg str text: the text to clean

    :arg set tags: set of allowed tags; defaults to
        ``bleach.sanitizer.ALLOWED_TAGS``

    :arg dict attributes: allowed attributes; can be a callable, list or dict;
        defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``

    :arg set protocols: set of allowed protocols for links; defaults
        to ``bleach.sanitizer.ALLOWED_PROTOCOLS``

    :arg bool strip: whether or not to strip disallowed elements

    :arg bool strip_comments: whether or not to strip HTML comments

    :arg CSSSanitizer css_sanitizer: instance with a "sanitize_css" method for
        sanitizing style attribute values and style text; defaults to None

    :returns: cleaned text as unicode

    """
    cleaner = Cleaner(
        tags=tags,
        attributes=attributes,
        protocols=protocols,
        strip=strip,
        strip_comments=strip_comments,
        css_sanitizer=css_sanitizer,
    )
    return cleaner.clean(text)


def linkify(text, callbacks=DEFAULT_CALLBACKS, skip_tags=None, parse_email=False):
    """Convert URL-like strings in an HTML fragment to links

    This function converts strings that look like URLs, domain names and email
    addresses in text that may be an HTML fragment to links, while preserving:

    1. links already in the string
    2. urls found in attributes
    3. email addresses

    linkify does a best-effort approach and tries to recover from bad
    situations due to crazy text.

    .. Note::

       If you're linking a lot of text and passing the same argument values or
       you want more configurability, consider using a
       :py:class:`bleach.linkifier.Linker` instance.

    .. Note::

       If you have text that you want to clean and then linkify, consider using
       the :py:class:`bleach.linkifier.LinkifyFilter` as a filter in the clean
       pass. That way you're not parsing the HTML twice.

    :arg str text: the text to linkify

    :arg list callbacks: list of callbacks to run when adjusting tag attributes;
        defaults to ``bleach.linkifier.DEFAULT_CALLBACKS``

    :arg list skip_tags: list of tags that you don't want to linkify the
        contents of; for example, you could set this to ``['pre']`` to skip
        linkifying contents of ``pre`` tags

    :arg bool parse_email: whether or not to linkify email addresses

    :returns: linkified text as unicode

    """
    linker = Linker(callbacks=callbacks, skip_tags=skip_tags, parse_email=parse_email)
    return linker.linkify(text)


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
    """Clean an HTML fragment, linkify it, and run a final safety check

    This is a single entry point for the common "sanitize a comment and then
    turn its URLs into links" workflow. The fragment is parsed once and run
    through three stages in a fixed order:

    1. clean the raw fragment with the given tag, attribute and protocol
       policy,
    2. linkify URLs and email addresses and run the ``callbacks`` on every
       link (newly created or already present),
    3. run the *same* clean policy one last time over the callback output.

    The third stage is the important one: attributes a callback adds or
    changes--including ``href``, ``target`` and ``rel``--must still pass the
    attribute allow-list and the allowed-protocol check. For example, a
    callback that rewrites ``href`` to a ``javascript:`` URL does not make it
    into the output.

    Link text returned by a callback via the ``_text`` key stays text, so any
    markup in it is escaped rather than interpreted as HTML. A callback that
    returns ``None`` drops the link and restores its text; that restored text
    is not linkified a second time.

    .. Note::

       If you're processing a lot of text with the same arguments, consider a
       :py:class:`bleach.clean_linkifier.CleanLinker` instance.

    .. Note::

       Composing the lower-level filters yourself (for example
       ``Cleaner(filters=[LinkifyFilter])``) does not add the final clean
       stage. When you do that, you are responsible for making sure the
       callback output is safe.

    :arg str text: the HTML fragment to process

    :arg set tags: set of allowed tags; defaults to
        ``bleach.sanitizer.ALLOWED_TAGS``

    :arg dict attributes: allowed attributes; can be a callable, list or dict;
        defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``

    :arg set protocols: set of allowed protocols for links; defaults
        to ``bleach.sanitizer.ALLOWED_PROTOCOLS``

    :arg bool strip: whether or not to strip disallowed elements

    :arg bool strip_comments: whether or not to strip HTML comments

    :arg CSSSanitizer css_sanitizer: instance with a "sanitize_css" method for
        sanitizing style attribute values and style text; defaults to None

    :arg list callbacks: list of callbacks to run when adjusting tag
        attributes; defaults to ``bleach.linkifier.DEFAULT_CALLBACKS``

    :arg list skip_tags: list of tags whose contents must not be linkified

    :arg bool parse_email: whether or not to linkify email addresses

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
