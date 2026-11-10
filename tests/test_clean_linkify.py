"""Tests for the clean -> linkify -> final-clean combined entry point."""

import pytest

from bleach import clean_linkify
from bleach.clean_linkifier import CleanLinker
from bleach.linkifier import LinkifyFilter
from bleach.sanitizer import ALLOWED_TAGS, Cleaner

# Allow the attributes the linkify callbacks may produce, otherwise the final
# clean stage drops them by design.
ATTRS = {"a": ["href", "title", "target", "rel"]}
TAGS = ALLOWED_TAGS | {"pre", "span"}


def test_typeerror_on_non_text():
    with pytest.raises(TypeError):
        clean_linkify(1)
    with pytest.raises(TypeError):
        clean_linkify(None)


def test_empty():
    assert clean_linkify("") == ""


def test_clean_happens_before_linkify():
    # Disallowed markup is escaped rather than being parsed as tags.
    out = clean_linkify("http://example.com <script>alert(1)</script>")
    assert out == (
        '<a href="http://example.com">http://example.com</a> '
        "&lt;script&gt;alert(1)&lt;/script&gt;"
    )


def test_new_and_existing_links_share_rules():
    out = clean_linkify(
        'text http://new.com and <a href="http://old.com">old</a>',
        attributes=ATTRS,
    )
    assert (
        out == 'text <a href="http://new.com" rel="nofollow">http://new.com</a> '
        'and <a href="http://old.com" rel="nofollow">old</a>'
    )


def test_email_uses_same_callbacks_and_policy():
    out = clean_linkify(
        "reach a@example.com", attributes=ATTRS, parse_email=True
    )
    assert out == 'reach <a href="mailto:a@example.com">a@example.com</a>'


def test_callback_invoked_once_per_link():
    calls = []

    def counting(attrs, new=False):
        calls.append((new, attrs.get((None, "href")), attrs.get("_text")))
        return attrs

    text = (
        "mail a@example.com and http://new.com plus "
        "<a href='http://old.com'>old</a>"
    )
    clean_linkify(text, attributes=ATTRS, callbacks=[counting], parse_email=True)

    assert len(calls) == 3
    assert (True, "mailto:a@example.com", "a@example.com") in calls
    assert (True, "http://new.com", "http://new.com") in calls
    assert (False, "http://old.com", "old") in calls


def test_none_drops_new_link_and_text_is_not_relinkified():
    def drop_new(attrs, new=False):
        return None if new else attrs

    out = clean_linkify("see http://example.com end", callbacks=[drop_new])
    assert out == "see http://example.com end"


def test_none_drops_existing_link_leaving_inner_text():
    def drop_all(attrs, new=False):
        return None

    out = clean_linkify(
        '<a href="http://example.com">label</a>', callbacks=[drop_all]
    )
    assert out == "label"


def test_none_on_email_restores_text_without_mailto():
    def drop_mailto(attrs, new=False):
        if attrs[(None, "href")].startswith("mailto:"):
            return None
        return attrs

    out = clean_linkify(
        "reach a@example.com", callbacks=[drop_mailto], parse_email=True
    )
    assert out == "reach a@example.com"
    assert "mailto" not in out


def test_callback_href_must_pass_final_protocol_check():
    def evil_href(attrs, new=False):
        attrs[(None, "href")] = "javascript:alert(1)"
        return attrs

    out = clean_linkify("http://example.com", callbacks=[evil_href])
    assert "javascript" not in out
    # The link tag survives, but the unsafe href is stripped.
    assert out == "<a>http://example.com</a>"


def test_callback_href_unicode_obfuscation_rejected():
    def evil_href(attrs, new=False):
        attrs[(None, "href")] = "java​script:alert(1)"
        return attrs

    out = clean_linkify("http://example.com", callbacks=[evil_href])
    assert "java" not in out


def test_callback_attribute_must_pass_final_allowlist():
    def add_class(attrs, new=False):
        attrs[(None, "class")] = "external"
        attrs[(None, "target")] = "_blank"
        return attrs

    # "class" is not allowed for <a>; the final clean drops it while keeping
    # the allowed "target".
    out = clean_linkify(
        "http://example.com", attributes=ATTRS, callbacks=[add_class]
    )
    assert "class=" not in out
    assert 'target="_blank"' in out


def test_legal_target_rel_combination_retained():
    from bleach.callbacks import nofollow, target_blank

    out = clean_linkify(
        "http://example.com", attributes=ATTRS, callbacks=[nofollow, target_blank]
    )
    assert 'target="_blank"' in out
    assert 'rel="nofollow"' in out


def test_existing_target_rel_combination_retained():
    out = clean_linkify(
        '<a href="http://example.com" target="_blank" rel="noopener">x</a>',
        attributes=ATTRS,
    )
    # The default nofollow callback appends rather than replaces the value.
    assert 'target="_blank" rel="noopener nofollow"' in out


def test_link_text_is_escaped_not_parsed_as_html():
    def weird_text(attrs, new=False):
        attrs["_text"] = '<b> & "x"'
        return attrs

    out = clean_linkify("http://example.com", callbacks=[weird_text])
    assert out == '<a href="http://example.com">&lt;b&gt; &amp; "x"</a>'


def test_no_double_escaping_of_entities():
    def passthrough(attrs, new=False):
        return attrs

    out = clean_linkify(
        '<a href="http://example.com?a=1&amp;b=2">x &amp; y</a>',
        attributes=ATTRS,
        callbacks=[passthrough],
    )
    assert out == '<a href="http://example.com?a=1&amp;b=2">x &amp; y</a>'


def test_skip_tags_blocks_new_links_only():
    out = clean_linkify(
        "<pre>http://example.com</pre> http://other.com",
        tags=TAGS,
        attributes=ATTRS,
        skip_tags={"pre"},
    )
    assert out == (
        "<pre>http://example.com</pre> "
        '<a href="http://other.com" rel="nofollow">http://other.com</a>'
    )


def test_nested_tags_inside_existing_link_preserved():
    out = clean_linkify(
        '<a href="http://example.com"><b>bold</b> link</a>', attributes=ATTRS
    )
    assert out == (
        '<a href="http://example.com" rel="nofollow"><b>bold</b> link</a>'
    )


def test_cleanlinker_instance_reuse():
    linker = CleanLinker(attributes=ATTRS)
    first = linker.clean_linkify("http://example.com")
    second = linker.clean_linkify("http://other.com")
    assert 'href="http://example.com"' in first
    assert 'href="http://other.com"' in second


def test_strip_disallowed_tags():
    out = clean_linkify(
        "http://example.com <span>kept text</span>", strip=True
    )
    assert "<span>" not in out
    assert "kept text" in out
    assert 'href="http://example.com"' in out


def test_final_clean_runs_after_callbacks_unlike_raw_filter_composition():
    def evil_href(attrs, new=False):
        attrs[(None, "href")] = "javascript:alert(1)"
        return attrs

    # The combined entry point removes the unsafe href in its final clean
    # stage, so the javascript: protocol never reaches the output.
    safe = clean_linkify("http://example.com", callbacks=[evil_href])
    assert "javascript" not in safe

    # Composing the lower-level filters by hand adds no final check, so a
    # callback-supplied href is emitted verbatim. The caller owns that
    # responsibility when they wire the filters together themselves.
    from functools import partial

    cleaner = Cleaner(filters=[partial(LinkifyFilter, callbacks=[evil_href])])
    raw = cleaner.clean("http://example.com")
    assert 'href="javascript:alert(1)"' in raw
