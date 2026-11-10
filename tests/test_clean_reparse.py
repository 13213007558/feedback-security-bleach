"""Regression corpus for clean -> serialize -> re-parse-as-fragment.

Each case starts from a fixed, deliberately small fragment and exercises an
HTML parser error-recovery or foreign-content boundary (misplaced tags,
comment boundaries, SVG/MathML transitions, raw-text/RCDATA elements, or
character entities). The interesting object is the *tree* obtained after a
second clean: the serialized output is fed back through the same HTML
fragment parser and the resulting tree is inspected, so a dangerous node or
attribute that only materializes after re-parsing is caught. String-level
checks such as ``"<script" not in text`` cannot tell an element from escaped
text and are therefore not used for the security assertions.

Scope note: the re-parse uses the vendored html5lib in its default
``parseFragment`` context, which is equivalent to inserting the string into an
ordinary HTML ``<body>`` (the fragment context element is a ``<div>``). This is
evidence about the backend parsing model shared by Bleach and html5lib only;
it does not claim to reproduce every browser's parser, integration-point, or
scripting behavior.
"""

import pytest

import bleach
from bleach._vendor import html5lib


HTML_NS = "http://www.w3.org/1999/xhtml"
SVG_NS = "http://www.w3.org/2000/svg"
MATHML_NS = "http://www.w3.org/1998/Math/MathML"

NS_PREFIX = {HTML_NS: "html", SVG_NS: "svg", MATHML_NS: "math"}

#: Active content / elements whose mere presence in the re-parsed tree would
#: mean script execution or a new embedding context. Local names only; tag
#: names are case-adjusted inside SVG, so the check is case-insensitive.
DANGEROUS_LOCAL_NAMES = frozenset(
    (
        "script",
        "style",
        "iframe",
        "object",
        "embed",
        "applet",
        "noembed",
        "noframes",
        "noscript",
        "meta",
        "base",
        "link",
        "form",
    )
)

#: img is only dangerous when smuggled through a boundary where it was not
#: allowed; cases that explicitly allow <img> list it as expected instead.
SMUGGLED_LOCAL_NAMES = frozenset(("img",))

#: Attributes that can carry a URL / browsing-context navigation.
URI_ATTRIBUTES = frozenset(
    ("href", "src", "xlink:href", "action", "formaction", "background", "poster")
)

#: Protocols that may appear on URI-bearing attributes in this corpus.
SAFE_PROTOCOLS = frozenset(("http", "https", "mailto"))


def _local_name(element):
    """Return the namespace-prefixed name used for structural assertions."""
    tag = element.tag
    if callable(tag):
        return "#comment"
    if tag == "DOCUMENT_FRAGMENT":
        return "#fragment"
    namespace, _, local = tag.rpartition("}")
    namespace = namespace[1:] if namespace else HTML_NS
    return f"{NS_PREFIX.get(namespace, namespace)}:{local}"


def _walk(element):
    """Depth-first traversal mirroring document order of the fragment."""
    yield element
    for child in list(element):
        yield from _walk(child)


def _structure(element):
    """Preorder list of (prefixed name, attributes) tuples."""
    structure = []
    for node in _walk(element):
        if not hasattr(node, "tag"):
            continue
        if callable(node.tag):
            structure.append(("#comment", dict(node.attrib)))
        elif node.tag != "DOCUMENT_FRAGMENT":
            structure.append((_local_name(node), dict(node.attrib)))
    return structure


def _all_text(element):
    """Collect text and tail of every element plus comment contents."""
    parts = []
    for node in _walk(element):
        if not hasattr(node, "tag"):
            continue
        if node.text:
            parts.append(node.text)
        if node.tail:
            parts.append(node.tail)
    return parts


def _dangerous_findings(element, allowed_active=()):
    """Return human-readable findings for dangerous nodes or attributes.

    The walk covers every namespace so an element that re-entered the HTML
    namespace after an SVG/MathML ejection is still inspected. Element local
    names passed in ``allowed_active`` are part of the case's explicit
    allowlist and are therefore expected (for example a case that allows
    ``style``); the dangerous default is still to flag them.
    """
    allowed_active = {name.lower() for name in allowed_active}
    findings = []
    for node in _walk(element):
        if (
            not hasattr(node, "tag")
            or callable(node.tag)
            or node.tag == "DOCUMENT_FRAGMENT"
        ):
            continue

        _, _, local = node.tag.rpartition("}")
        if (
            local.lower() in DANGEROUS_LOCAL_NAMES
            and local.lower() not in allowed_active
        ):
            findings.append(f"dangerous element {_local_name(node)}")
        if (
            local.lower() in SMUGGLED_LOCAL_NAMES
            and local.lower() not in allowed_active
        ):
            findings.append(f"smuggled element {_local_name(node)}")

        for namespaced_name, value in node.attrib.items():
            _, _, attr_name = namespaced_name.rpartition("}")
            if attr_name.startswith("on"):
                findings.append(
                    f"event handler attribute {attr_name}={value!r} "
                    f"on {_local_name(node)}"
                )
            if attr_name.lower() in URI_ATTRIBUTES:
                stripped = value.strip()
                if ":" in stripped:
                    scheme = stripped.split(":", 1)[0].lower()
                    if scheme not in SAFE_PROTOCOLS:
                        findings.append(
                            f"disallowed URI scheme {scheme!r} in {attr_name} "
                            f"on {_local_name(node)}"
                        )
    return findings


#: Fixed corpus. Every entry documents why the dangerous node or attribute
#: could come back after serialization, instead of asserting only on output
#: strings. ``expected_structure`` is the tree after the second clean;
#: ``expected_text`` lists substrings that must survive in text nodes.
CORPUS = [
    pytest.param(
        {
            "id": "misnested_inline_tags",
            "data": (
                "<p><b>bold <i>both</b> only</i></p>"
                "<p>plain <em>text</em></p>"
            ),
            "clean_kwargs": {},
            "risk": (
                "misnested <b>/<i> and stray </p> tokens trigger active-formatting "
                "reconstruction; a re-open of a dropped element during tree repair "
                "could resurrect active content in a different parent"
            ),
            "expected_structure": [
                ("html:b", {}),
                ("html:i", {}),
                ("html:i", {}),
                ("html:em", {}),
            ],
            "expected_text": ["bold ", "both", " only", "plain ", "text"],
            "expected_anchors": [],
        },
        id="misnested_inline_tags",
    ),
    pytest.param(
        {
            "id": "stray_end_tag_and_rcdata_boundary",
            "data": (
                "</p>tail text<textarea></textarea>"
                "<img src=x onerror=alert(1)><p><strong>keep</strong> me</p>"
            ),
            "clean_kwargs": {"tags": {"textarea", "p", "em", "strong"}},
            "risk": (
                "a stray </p> is recovered as a real paragraph, and the empty "
                "<textarea> switches the tokenizer into RCDATA; markup following "
                "the raw-text element could be swallowed or, on re-parse, become "
                "a live <img onerror> instead of escaped text"
            ),
            "expected_structure": [
                ("html:p", {}),
                ("html:textarea", {}),
                ("html:p", {}),
                ("html:strong", {}),
            ],
            "expected_text": [
                "tail text",
                "<img src=x onerror=alert(1)>",
                "keep",
                " me",
            ],
            "expected_anchors": [],
        },
        id="stray_end_tag_and_rcdata_boundary",
    ),
    pytest.param(
        {
            "id": "abrupt_comment_boundaries",
            "data": "lead <!-- --><img src=x onerror=alert(1)><!-- abrupt",
            "clean_kwargs": {"tags": {"em"}, "strip_comments": False},
            "risk": (
                "an unterminated comment is auto-closed at EOF and comment text is "
                "kept verbatim; a --> smuggled inside an attribute or comment on "
                "the first pass could terminate the comment and release the <img> "
                "as a real element when the fragment is parsed again"
            ),
            "expected_structure": [
                ("#comment", {}),
                ("#comment", {}),
            ],
            "expected_text": ["lead ", "<img src=x onerror=alert(1)>"],
            "expected_anchors": [],
        },
        id="abrupt_comment_boundaries",
    ),
    pytest.param(
        {
            "id": "bogus_comment_and_bracketed_text",
            "data": "<!not-a-comment><p>hi <em>there</em></p>",
            "clean_kwargs": {"tags": {"em"}, "strip_comments": False},
            "risk": (
                "a bogus <! comment has no trailing > in source; serializer-added "
                "delimiters must stay balanced on re-parse so following markup is "
                "not absorbed into the comment and legitimate text lost or "
                "reinterpreted"
            ),
            "expected_structure": [
                ("#comment", {}),
                ("html:em", {}),
            ],
            "expected_text": ["not-a-comment", "<p>hi ", "there"],
            "expected_anchors": [],
        },
        id="bogus_comment_and_bracketed_text",
    ),
    pytest.param(
        {
            "id": "svg_ejection_style_comment",
            "data": (
                "<svg></p><style><!--</style>"
                "<img src=x onerror=alert(1)></svg>visible text"
            ),
            "clean_kwargs": {"tags": {"svg", "p", "style"}, "strip_comments": False},
            "allowed_active": ["style"],
            "risk": (
                "the </p> forces HTML integration inside SVG and <style> enters raw "
                "text mode; browsers eject the trailing <img> out of the foreign "
                "namespace, where it would execute onerror. GHSA-vv2x-vrpj-qqpq"
            ),
            "expected_structure": [
                ("svg:svg", {}),
                ("html:p", {}),
                ("html:style", {}),
            ],
            "expected_text": ["visible text"],
            "expected_anchors": [],
        },
        id="svg_ejection_style_comment",
    ),
    pytest.param(
        {
            "id": "svg_img_ejection_allowed",
            "data": "<svg><rect></rect><img src=x onerror=alert(1)></svg>tail",
            "clean_kwargs": {
                "tags": {"svg", "rect", "img"},
                "attributes": {"img": ["src"]},
            },
            "allowed_active": ["img"],
            "risk": (
                "HTML <img> breaks out of SVG foreign content, so its namespace and "
                "parent change; onerror must be dropped at the boundary and the "
                "allowed src must survive on the ejected HTML element"
            ),
            "expected_structure": [
                ("svg:svg", {}),
                ("svg:rect", {}),
                ("html:img", {"src": "x"}),
            ],
            "expected_text": ["tail"],
            "expected_anchors": [],
        },
        id="svg_img_ejection_allowed",
    ),
    pytest.param(
        {
            "id": "math_ejection_with_link",
            "data": (
                "<math><mi>x</mi><p>out</p></math>"
                '<a href="https://example.com/m">m link</a>'
            ),
            "clean_kwargs": {
                "tags": {"math", "mi", "p", "a"},
                "attributes": {"a": ["href"]},
            },
            "risk": (
                "a block <p> inside MathML ejects back into HTML; the namespace "
                "switch can change which attributes a later element accepts, so the "
                "allowed link must keep its href while no foreign-namespace wrapper "
                "is fabricated"
            ),
            "expected_structure": [
                ("math:math", {}),
                ("math:mi", {}),
                ("html:p", {}),
                ("html:a", {"href": "https://example.com/m"}),
            ],
            "expected_text": ["x", "out", "m link"],
            "expected_anchors": [("https://example.com/m", "m link")],
        },
        id="math_ejection_with_link",
    ),
    pytest.param(
        {
            "id": "svg_foreign_object_camel_case",
            "data": (
                '<svg><foreignobject id="f"><p>inside</p>'
                "<img src=x onerror=alert(1)></foreignobject></svg>"
                "<p>outside</p>"
            ),
            "clean_kwargs": {
                "tags": {"svg", "foreignobject", "p"},
                "attributes": {"*": ["id"]},
            },
            "risk": (
                "foreignObject is an HTML integration point: html5lib case-adjusts "
                "the token name to camelCase, so a lowercase-only allowlist match "
                "escapes the whole element as text and the inner <img> is only kept "
                "inert by escaping; a later serializer/parser change could release it"
            ),
            "expected_structure": [
                ("svg:svg", {}),
                ("svg:foreignObject", {"id": "f"}),
                ("html:p", {}),
                ("html:p", {}),
            ],
            "expected_text": ["inside", "outside"],
            "expected_anchors": [],
        },
        id="svg_foreign_object_camel_case",
    ),
    pytest.param(
        {
            "id": "svg_adjusted_tag_name_gradient",
            "data": '<svg><lineargradient id="g"></lineargradient><rect/></svg>',
            "clean_kwargs": {
                "tags": {"svg", "lineargradient"},
                "attributes": {"*": ["id"]},
            },
            "risk": (
                "linearGradient is another html5lib SVG name-adjustment; an allowlist "
                "miss turns the element into text whose angle brackets, if ever "
                "emitted without escaping, would parse as a real SVG element again"
            ),
            "expected_structure": [
                ("svg:svg", {}),
                ("svg:linearGradient", {"id": "g"}),
            ],
            "expected_text": [],
            "expected_anchors": [],
        },
        id="svg_adjusted_tag_name_gradient",
    ),
    pytest.param(
        {
            "id": "textarea_rcdata_smuggled_markup",
            "data": "<textarea><img src=x onerror=alert(1)></textarea><em>safe</em>",
            "clean_kwargs": {"tags": {"textarea", "em"}},
            "risk": (
                "inside RCDATA the <img> is raw text; RCDATA only ends at the first "
                "</textarea>, so a missing or renamed end tag on the first pass could "
                "make the markup live when the serialized fragment is parsed again"
            ),
            "expected_structure": [
                ("html:textarea", {}),
                ("html:em", {}),
            ],
            "expected_text": ["<img src=x onerror=alert(1)>", "safe"],
            "expected_anchors": [],
        },
        id="textarea_rcdata_smuggled_markup",
    ),
    pytest.param(
        {
            "id": "svg_style_raw_text_ejection",
            "data": (
                "<svg><style><!--</style><img src=x onerror=alert(1)>-->"
                "</style></svg>tail text"
            ),
            "clean_kwargs": {"tags": {"svg", "style"}},
            "allowed_active": ["style"],
            "risk": (
                "SVG <style> is raw text and does not eject, while an HTML <style> "
                "would; the namespace chosen on re-parse decides whether the inner "
                "<img> stays inert text or becomes a real element, and the spurious "
                "comment close must not swallow the trailing body text"
            ),
            "expected_structure": [
                ("svg:svg", {}),
                ("svg:style", {}),
            ],
            "expected_text": ["tail text"],
            "expected_anchors": [],
        },
        id="svg_style_raw_text_ejection",
    ),
    pytest.param(
        {
            "id": "entities_and_obfuscated_uri",
            "data": (
                "<p>a &amp; b &#60;img src=x onerror=1&#62; &nbsp;</p>"
                '<a href="javascript:alert(1)">bad</a>'
                '<a href="https://example.com/?q=1&amp;q=2">good link</a>'
            ),
            "clean_kwargs": {"tags": {"p", "a"}, "attributes": {"a": ["href"]}},
            "risk": (
                "numeric entities decode to literal angle brackets in text, while "
                "ampersands must stay escaped so the <img> never tokenizes on "
                "re-parse; the javascript: href is stripped, but entity/whitespace "
                "obfuscation of the scheme could smuggle it back as a live attribute"
            ),
            "expected_structure": [
                ("html:p", {}),
                ("html:a", {}),
                ("html:a", {"href": "https://example.com/?q=1&q=2"}),
            ],
            "expected_text": [
                "a & b <img src=x onerror=1> \xa0",
                "bad",
                "good link",
            ],
            "expected_anchors": [
                (None, "bad"),
                ("https://example.com/?q=1&q=2", "good link"),
            ],
        },
        id="entities_and_obfuscated_uri",
    ),
]


def _reparse(serialized):
    """Parse cleaned output again in the ordinary HTML body-fragment context."""
    return html5lib.parseFragment(serialized)


def _render_tree(element):
    """Stable indented rendering kept for failure output and debugging."""
    lines = []

    def render(node, depth):
        prefix = "  " * depth
        if not hasattr(node, "tag"):
            return
        if callable(node.tag):
            lines.append(f"{prefix}#comment {node.text!r}")
        elif node.tag == "DOCUMENT_FRAGMENT":
            lines.append(f"{prefix}#fragment")
        else:
            lines.append(f"{prefix}{_local_name(node)} {dict(node.attrib)}")
            if node.text:
                lines.append(f"{prefix}  #text {node.text!r}")
        for child in list(node):
            render(child, depth + 1)
        if node.tail:
            lines.append(f"{prefix}  #tail {node.tail!r}")

    render(element, 0)
    return "\n".join(lines)


@pytest.mark.parametrize("case", CORPUS)
def test_clean_serialize_reparse_corpus(case):
    """Fixed corpus checked on the twice-cleaned, re-parsed fragment tree."""
    data = case["data"]
    kwargs = case["clean_kwargs"]

    once = bleach.clean(data, **kwargs)
    twice = bleach.clean(once, **kwargs)

    tree_once = _reparse(once)
    tree_twice = _reparse(twice)

    findings = _dangerous_findings(
        tree_twice, allowed_active=case.get("allowed_active", ())
    )
    assert findings == [], (
        "dangerous nodes/attributes present after re-parse\n"
        f"case: {case['id']}\n"
        f"risk: {case['risk']}\n"
        f"original input: {data!r}\n"
        f"first clean: {once!r}\n"
        f"second clean: {twice!r}\n"
        f"first-pass tree:\n{_render_tree(tree_once)}\n"
        f"second-pass tree:\n{_render_tree(tree_twice)}\n"
        f"findings: {findings}"
    )

    assert _structure(tree_twice) == case["expected_structure"], (
        "unexpected tree after clean -> serialize -> re-parse\n"
        f"case: {case['id']}\n"
        f"original input: {data!r}\n"
        f"first clean: {once!r}\n"
        f"second clean: {twice!r}\n"
        f"first-pass tree:\n{_render_tree(tree_once)}\n"
        f"second-pass tree:\n{_render_tree(tree_twice)}"
    )

    surviving_text = _all_text(tree_twice)
    joined_text = "".join(surviving_text)
    for expected_text in case["expected_text"]:
        assert expected_text in joined_text, (
            "allowed body text was emptied or altered\n"
            f"case: {case['id']}\n"
            f"missing text: {expected_text!r}\n"
            f"surviving text: {surviving_text}\n"
            f"second-pass tree:\n{_render_tree(tree_twice)}"
        )

    links = [
        (element.attrib.get("href"), (element.text or ""))
        for element in _walk(tree_twice)
        if hasattr(element, "tag")
        and not callable(element.tag)
        and element.tag == f"{{{HTML_NS}}}a"
    ]
    assert links == case["expected_anchors"], (
        "allowed links were dropped or rewritten\n"
        f"case: {case['id']}\n"
        f"second-pass tree:\n{_render_tree(tree_twice)}"
    )


def test_svg_case_adjusted_tag_name_matches_lowercase_allowlist():
    """html5lib-adjusted SVG camelCase names must match lowercase allowlists.

    Before this was fixed, ``foreignobject`` and ``lineargradient`` were
    escaped as text because the treewalker emits ``foreignObject`` and
    ``linearGradient``; the element then only survived as inert escaped text,
    and any downstream consumer emitting it without escaping would re-create
    a live foreign element.
    """
    cleaned = bleach.clean(
        '<svg><foreignobject id="f"><p>x</p></foreignobject>'
        '<lineargradient id="g"></lineargradient></svg>',
        tags={"svg", "foreignobject", "lineargradient", "p"},
        attributes={"*": ["id"]},
    )
    tree = _reparse(cleaned)
    structure = _structure(tree)

    assert ("svg:foreignObject", {"id": "f"}) in structure
    assert ("svg:linearGradient", {"id": "g"}) in structure
    assert ("html:p", {}) in structure
    assert _dangerous_findings(tree) == []

    # Before the fix the first pass emitted escaped text, so a second clean
    # produced yet another shape; pin idempotency as part of the regression.
    assert bleach.clean(cleaned, tags={
        "svg",
        "foreignobject",
        "lineargradient",
        "p",
    }, attributes={"*": ["id"]}) == cleaned


def test_reparse_context_is_body_fragment():
    """Pin the parsing contract the corpus relies on.

    parseFragment uses a <div> context, i.e. the string is interpreted as
    body-level fragment content; head-only elements are relocated and no
    document/head scaffolding is invented.
    """
    tree = _reparse("<title>t</title><p>x</p>")
    names = [name for name, _ in _structure(tree)]
    assert names == ["html:title", "html:p"]
