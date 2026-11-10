from functools import partial

import pytest

tinycss2 = pytest.importorskip("tinycss2")

from bleach import clean  # noqa
from bleach.css_sanitizer import CSSSanitizer  # noqa


clean = partial(clean, tags={"p"}, attributes=["style"])


@pytest.mark.parametrize(
    "data, styles, expected",
    [
        (
            '<p style="font-family: Arial; color: red; float: left; background-color: red;">bar</p>',
            ["color"],
            '<p style="color: red;">bar</p>',
        ),
        (
            '<p style="border: 1px solid blue; color: red; float: left;">bar</p>',
            ["color"],
            '<p style="color: red;">bar</p>',
        ),
        (
            '<p style="border: 1px solid blue; color: red; float: left;">bar</p>',
            ["color", "float"],
            '<p style="color: red; float: left;">bar</p>',
        ),
        (
            '<p style="color: red; float: left; padding: 1em;">bar</p>',
            ["color", "float"],
            '<p style="color: red; float: left;">bar</p>',
        ),
        (
            '<p style="color: red; float: left; padding: 1em;">bar</p>',
            ["color"],
            '<p style="color: red;">bar</p>',
        ),
        # Handle leading - in attributes
        pytest.param(
            '<p style="cursor: -moz-grab;">bar</p>',
            ["cursor"],
            '<p style="cursor: -moz-grab;">bar</p>',
        ),
        # Handle () in attributes
        (
            '<p style="color: hsl(30,100%,50%);">bar</p>',
            ["color"],
            '<p style="color: hsl(30,100%,50%);">bar</p>',
        ),
        (
            '<p style="color: rgba(255,0,0,0.4);">bar</p>',
            ["color"],
            '<p style="color: rgba(255,0,0,0.4);">bar</p>',
        ),
        # Handle ' in attributes
        pytest.param(
            "<p style=\"text-overflow: ',' ellipsis;\">bar</p>",
            ["text-overflow"],
            "<p style='text-overflow: \",\" ellipsis;'>bar</p>",
        ),
        # Handle " in attributes
        pytest.param(
            "<p style='text-overflow: \",\" ellipsis;'>bar</p>",
            ["text-overflow"],
            "<p style='text-overflow: \",\" ellipsis;'>bar</p>",
        ),
        (
            "<p style='font-family: \"Arial\";'>bar</p>",
            ["font-family"],
            "<p style='font-family: \"Arial\";'>bar</p>",
        ),
        # Handle non-ascii characters in attributes
        (
            '<p style="font-family: \u30e1\u30a4\u30ea\u30aa; color: blue;">bar</p>',
            ["color"],
            '<p style="color: blue;">bar</p>',
        ),
    ],
)
def test_allowed_css(data, styles, expected):
    css_sanitizer = CSSSanitizer(allowed_css_properties=styles)
    assert clean(data, css_sanitizer=css_sanitizer) == expected


def test_valid_css():
    """The sanitizer should fix missing CSS values."""
    css_sanitizer = CSSSanitizer(allowed_css_properties=["color", "float"])
    assert (
        clean('<p style="float: left; color: ">foo</p>', css_sanitizer=css_sanitizer)
        == '<p style="float: left; color: ;">foo</p>'
    )
    assert (
        clean('<p style="color: float: left;">foo</p>', css_sanitizer=css_sanitizer)
        == '<p style="color: float: left;">foo</p>'
    )


@pytest.mark.parametrize(
    "data, expected",
    [
        # No url--unchanged
        (
            '<p style="background: #00D;">foo</p>',
            '<p style="background: #00D;">foo</p>',
        ),
        (
            '<p style="background: url(topbanner.png) #00D;">foo</p>',
            '<p style="background: url(topbanner.png) #00D;">foo</p>',
        ),
        (
            "<p style=\"background: url('topbanner.png') #00D;\">foo</p>",
            "<p style='background: url(\"topbanner.png\") #00D;'>foo</p>",
        ),
        (
            "<p style='background: url(\"topbanner.png\") #00D;'>foo</p>",
            "<p style='background: url(\"topbanner.png\") #00D;'>foo</p>",
        ),
        # Verify urls with spacing
        (
            "<p style=\"background: url(  'topbanner.png') #00D;\">foo</p>",
            "<p style='background: url(  \"topbanner.png\") #00D;'>foo</p>",
        ),
        (
            "<p style=\"background: url('topbanner.png'  ) #00D;\">foo</p>",
            "<p style='background: url(\"topbanner.png\"  ) #00D;'>foo</p>",
        ),
        (
            "<p style=\"background: url(  'topbanner.png'  ) #00D;\">foo</p>",
            "<p style='background: url(  \"topbanner.png\"  ) #00D;'>foo</p>",
        ),
        (
            "<p style=\"background: url (  'topbanner.png'  ) #00D;\">foo</p>",
            "<p style='background: url (  \"topbanner.png\"  ) #00D;'>foo</p>",
        ),
        # Verify urls with character entities
        (
            "<p style=\"background: url&#x09;('topbanner.png') #00D;\">foo</p>",
            '<p style="background: url&#x09;">foo</p>',
        ),
    ],
)
def test_urls(data, expected):
    css_sanitizer = CSSSanitizer(allowed_css_properties=["background"])
    assert clean(data, css_sanitizer=css_sanitizer) == expected


def test_style_hang():
    """The sanitizer should not hang on any inline styles"""
    style = [
        "margin-top: 0px;",
        "margin-right: 0px;",
        "margin-bottom: 1.286em;",
        "margin-left: 0px;",
        "padding-top: 15px;",
        "padding-right: 15px;",
        "padding-bottom: 15px;",
        "padding-left: 15px;",
        "border-top-width: 1px;",
        "border-right-width: 1px;",
        "border-bottom-width: 1px;",
        "border-left-width: 1px;",
        "border-top-style: dotted;",
        "border-right-style: dotted;",
        "border-bottom-style: dotted;",
        "border-left-style: dotted;",
        "border-top-color: rgb(203, 200, 185);",
        "border-right-color: rgb(203, 200, 185);",
        "border-bottom-color: rgb(203, 200, 185);",
        "border-left-color: rgb(203, 200, 185);",
        "background-image: initial;",
        "background-attachment: initial;",
        "background-origin: initial;",
        "background-clip: initial;",
        "background-color: rgb(246, 246, 242);",
        "overflow-x: auto;",
        "overflow-y: auto;",
        "font: italic small-caps bolder condensed 16px/3 cursive;",
        "background-position: initial initial;",
        "background-repeat: initial initial;",
    ]
    html = '<p style="%s">Hello world</p>' % " ".join(style)
    styles = [
        "border",
        "float",
        "overflow",
        "min-height",
        "vertical-align",
        "white-space",
        "margin",
        "margin-left",
        "margin-top",
        "margin-bottom",
        "margin-right",
        "padding",
        "padding-left",
        "padding-top",
        "padding-bottom",
        "padding-right",
        "background",
        "background-color",
        "font",
        "font-size",
        "font-weight",
        "text-align",
        "text-transform",
    ]

    expected = (
        '<p style="'
        "margin-top: 0px; "
        "margin-right: 0px; "
        "margin-bottom: 1.286em; "
        "margin-left: 0px; "
        "padding-top: 15px; "
        "padding-right: 15px; "
        "padding-bottom: 15px; "
        "padding-left: 15px; "
        "background-color: rgb(246, 246, 242); "
        "font: italic small-caps bolder condensed 16px/3 cursive;"
        '">Hello world</p>'
    )

    css_sanitizer = CSSSanitizer(allowed_css_properties=styles)
    assert clean(html, css_sanitizer=css_sanitizer) == expected


@pytest.mark.parametrize(
    "data, styles, expected",
    [
        (
            '<p style="font-family: Droid Sans, serif; white-space: pre-wrap;">text</p>',
            ["font-family", "white-space"],
            '<p style="font-family: Droid Sans, serif; white-space: pre-wrap;">text</p>',
        ),
        (
            "<p style=\"content: '&nbsp;';\">text</p>",
            ["content"],
            # This seems wrong, but it's right. Character entities aren't a
            # thing in CSS, so this is treated as text.
            "<p style='content: \"&amp;nbsp;\";'>text</p>",
        ),
    ],
)
def test_css_parsing_with_entities(data, styles, expected):
    """The sanitizer should be ok with character entities"""
    css_sanitizer = CSSSanitizer(allowed_css_properties=styles)
    assert (
        clean(
            data, tags={"p"}, attributes={"p": ["style"]}, css_sanitizer=css_sanitizer
        )
        == expected
    )


HTTPS_SANITIZER = CSSSanitizer(
    allowed_css_properties=["background", "background-image", "color", "content"],
    allowed_url_protocols=["https"],
)


def _collect_url_tokens(tokens):
    """Walk a tinycss2 token tree and collect every URL-like value."""
    urls = []
    for token in tokens:
        if token.type == "url":
            urls.append(token.value)
        elif token.type == "function":
            if token.lower_name == "url":
                urls.extend(
                    arg.value for arg in token.arguments if arg.type == "string"
                )
            elif token.lower_name in (
                "image-set",
                "-webkit-image-set",
                "image",
            ):
                urls.extend(
                    arg.value
                    for arg in token.arguments
                    if arg.type == "string"
                )
                urls.extend(_collect_url_tokens(token.arguments))
            else:
                urls.extend(_collect_url_tokens(token.arguments))
        elif token.type.endswith(" block"):
            urls.extend(_collect_url_tokens(token.content))
    return urls


def _sanitized_declarations(style, css_sanitizer):
    return [
        token
        for token in tinycss2.parse_declaration_list(
            css_sanitizer.sanitize_css(style)
        )
        if token.type == "declaration"
    ]


@pytest.mark.parametrize(
    "style, expected_urls",
    [
        # Bare url token, quoted url() and case-insensitive protocols
        (
            "background-image: url(https://example.com/a.png)",
            ["https://example.com/a.png"],
        ),
        (
            'background-image: url("https://example.com/a.png")',
            ["https://example.com/a.png"],
        ),
        (
            "background-image: url(HTTPS://example.com/a.png)",
            ["HTTPS://example.com/a.png"],
        ),
        # In-page fragments are allowed, including quoted and padded ones
        ("background-image: url(#fragment)", ["#fragment"]),
        ('background-image: url(" #fragment ")', [" #fragment "]),
        # image-set() string sources and nested url() sources
        (
            'background: image-set("https://x/a" 1x, url("https://x/b") 2x)',
            ["https://x/a", "https://x/b"],
        ),
        (
            'background: -webkit-image-set("https://x/a" 1x)',
            ["https://x/a"],
        ),
        # image() string source and its non-URL direction/color arguments
        (
            'background: image("https://x/a", ltr)',
            ["https://x/a"],
        ),
        # Nested functions keep working when their URLs are allowed
        (
            'background: linear-gradient(0deg, rgba(0, 0, 0, 0.2), '
            'url("https://x/y.png"))',
            ["https://x/y.png"],
        ),
        (
            "background: cross-fade(url(https://a), url(https://b), 50%)",
            ["https://a", "https://b"],
        ),
        # Escapes are resolved by tinycss2 before the protocol comparison
        (
            r'background-image: url("https\3a //example.com/a")',
            ["https://example.com/a"],
        ),
    ],
)
def test_allowed_url_protocols_keeps_allowed_urls(style, expected_urls):
    sanitized = HTTPS_SANITIZER.sanitize_css(style)
    declarations = _sanitized_declarations(style, HTTPS_SANITIZER)

    assert len(declarations) == 1
    assert _collect_url_tokens(declarations[0].value) == expected_urls
    # Serializing again must not change anything (idempotent output).
    assert HTTPS_SANITIZER.sanitize_css(sanitized) == sanitized


@pytest.mark.parametrize(
    "style",
    [
        # Relative and protocol-relative URLs have no trusted base URL
        "background-image: url(topbanner.png)",
        "background-image: url(//host/a.png)",
        'background-image: url("topbanner.png")',
        # Disallowed protocols, including escaped and uppercase spellings that
        # tinycss2 resolves before the value check runs
        "background-image: url(http://example.com/a.png)",
        r"background-image: url(java\73 cript:alert)",
        r'background-image: url("java\73 cript:alert")',
        r"background-image: url(JAVA\53 CRIPT:alert)",
        r'background-image: url("JAVA\53 CRIPT:alert")',
        r"background-image: url(java\000073cript:alert)",
        # image-set() string sources are URLs too
        'background: image-set("relative.png" 1x)',
        'background: image-set("//host/a" 1x)',
        'background: image-set("http://x/a" 1x)',
        'background: image("relative.png")',
        "background: image(//host/a)",
        'background: image("https://a", var(--x))',
        # Nested URL in another function cannot bypass the policy
        'background: linear-gradient(red, url("//x/y.png"))',
        'background: cross-fade(url(//a), url(https://b), 50%)',
        # Substitution functions are not resolvable without a browser
        "background: var(--x)",
        "background: env(bg)",
        "background: var(--bg, url(https://ok))",
        "background: linear-gradient(var(--c), url(https://ok))",
        # Bad tokens and unparseable URL arguments
        "background: url(bad",
        'background: url("unterminated)',
        'background: url("a" "b")',
        "background: url()",
        # image-set sources that cannot be interpreted as an image source
        'background: image-set("https://a" garbage)',
        "background: image-set(123 1x)",
        # NUL (mapped to U+FFFD by tokenization) and ASCII control characters
        'background: url("https://a' + chr(0) + 'b")',
        'background: url("a' + chr(1) + 'b")',
        'background: url("a' + chr(0x7F) + 'b")',
        'background: url("a' + chr(9) + 'b")',
        r'background: url("a\000009b")',
    ],
)
def test_allowed_url_protocols_drops_bad_declarations(style):
    assert HTTPS_SANITIZER.sanitize_css(style) == ""


def test_allowed_url_protocols_mixed_declarations():
    style = (
        "color: red; "
        'background: url(//evil/path); '
        'background-image: url("https://ok.example/pic.png"); '
        "color: blue"
    )
    sanitized = HTTPS_SANITIZER.sanitize_css(style)
    declarations = _sanitized_declarations(style, HTTPS_SANITIZER)

    assert [token.lower_name for token in declarations] == [
        "color",
        "background-image",
        "color",
    ]
    assert _collect_url_tokens(declarations[1].value) == [
        "https://ok.example/pic.png"
    ]
    assert "//evil/path" not in sanitized
    assert HTTPS_SANITIZER.sanitize_css(sanitized) == sanitized


def test_allowed_url_protocols_preserves_serialization():
    style = (
        "color: red /* keep me */; "
        'background: url(https://example.com/a.png) !important; '
        "color: blue"
    )
    sanitizer = CSSSanitizer(
        allowed_css_properties=["color", "background"],
        allowed_url_protocols={"HTTPS"},
    )

    sanitized = sanitizer.sanitize_css(style)
    assert "/* keep me */" in sanitized
    assert "!important" in sanitized
    assert sanitized.count("color:") == 2
    assert sanitized.count("background:") == 1
    assert sanitizer.sanitize_css(sanitized) == sanitized


def test_allowed_url_protocols_ignores_non_url_strings():
    style = (
        'font-family: "url(https://evil.example)"; '
        "content: 'javascript:alert(1)'; "
        'background: image-set("https://a" type("image/png"))'
    )
    sanitizer = CSSSanitizer(
        allowed_css_properties=["font-family", "content", "background"],
        allowed_url_protocols=["https"],
    )

    sanitized = sanitizer.sanitize_css(style)
    declarations = _sanitized_declarations(style, sanitizer)
    assert [token.lower_name for token in declarations] == [
        "font-family",
        "content",
        "background",
    ]
    assert sanitizer.sanitize_css(sanitized) == sanitized


def test_allowed_url_protocols_applies_through_cleaner():
    data = (
        '<p style="color: red; '
        'background: url(//evil.example/pic); '
        'background-image: url(https://ok.example/pic.png)">bar</p>'
    )
    expected = (
        '<p style="color: red; '
        'background-image: url(https://ok.example/pic.png);">bar</p>'
    )
    assert clean(data, css_sanitizer=HTTPS_SANITIZER) == expected


def test_allowed_url_protocols_custom_properties_are_checked():
    sanitizer = CSSSanitizer(
        allowed_css_properties=["background"],
        allowed_url_protocols=["https"],
    )
    assert sanitizer.sanitize_css("background: url(javascript:alert)") == ""


def test_default_behavior_is_unchanged_without_url_policy():
    sanitizer = CSSSanitizer(allowed_css_properties=["background"])
    style = "background: url(topbanner.png) #00D"
    assert sanitizer.sanitize_css(style) == style + ";"
    assert (
        clean(
            '<p style="background: url(topbanner.png) #00D;">foo</p>',
            css_sanitizer=sanitizer,
        )
        == '<p style="background: url(topbanner.png) #00D;">foo</p>'
    )
