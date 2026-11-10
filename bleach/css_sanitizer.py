import tinycss2


# tinycss2 follows the CSS spec input preprocessing rules and replaces NUL
# characters (including escaped NULs) with U+FFFD before tokenization, so a
# replacement character in a parsed value is evidence of a NUL in the source.
NUL_REPLACEMENT_CHARACTER = "\ufffd"

SUBSTITUTION_FUNCTIONS = frozenset(("var", "env"))
# Tokens used after an image source in image-set(): optional commas and
# resolution hints (1x, 600dpi, ...).
IMAGE_SET_MARKER_TYPES = frozenset(
    ("whitespace", "comment", "literal", "dimension")
)


def _contains_control_character(value):
    """Return whether value contains a NUL or another ASCII control character."""
    return any(
        ord(char) < 0x20 or ord(char) == 0x7F or char == NUL_REPLACEMENT_CHARACTER
        for char in value
    )


def _url_is_allowed(url, allowed_url_protocols):
    """Validate one parsed URL value against the allowed protocol set.

    Leading and trailing whitespace is ignored. In-page fragments are always
    allowed, while relative paths and protocol-relative ("//host") URLs are
    rejected because there is no trusted base URL to resolve them against.
    """
    url = url.strip()
    if not url:
        return False
    if _contains_control_character(url):
        return False
    if url.startswith("#"):
        return True

    scheme, separator, _ = url.partition(":")
    if not separator:
        return False
    return scheme.lower() in allowed_url_protocols


ALLOWED_CSS_PROPERTIES = frozenset(
    (
        "azimuth",
        "background-color",
        "border-bottom-color",
        "border-collapse",
        "border-color",
        "border-left-color",
        "border-right-color",
        "border-top-color",
        "clear",
        "color",
        "cursor",
        "direction",
        "display",
        "elevation",
        "float",
        "font",
        "font-family",
        "font-size",
        "font-style",
        "font-variant",
        "font-weight",
        "height",
        "letter-spacing",
        "line-height",
        "overflow",
        "pause",
        "pause-after",
        "pause-before",
        "pitch",
        "pitch-range",
        "richness",
        "speak",
        "speak-header",
        "speak-numeral",
        "speak-punctuation",
        "speech-rate",
        "stress",
        "text-align",
        "text-decoration",
        "text-indent",
        "unicode-bidi",
        "vertical-align",
        "voice-family",
        "volume",
        "white-space",
        "width",
    )
)


ALLOWED_SVG_PROPERTIES = frozenset(
    (
        "fill",
        "fill-opacity",
        "fill-rule",
        "stroke",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-opacity",
    )
)


class CSSSanitizer:
    """Sanitizes CSS declaration lists.

    :arg allowed_css_properties: set of CSS properties to allow
    :arg allowed_svg_properties: set of SVG presentation attributes to allow
    :arg allowed_url_protocols: optional set (or other iterable) of URL
        protocols to allow in URL values. Protocol names are compared case-
        insensitively without the trailing colon, for example ``{"https"}``.
        In-page fragment URLs (``#fragment``) are always allowed when this is
        set. Relative paths and protocol-relative (``//host``) URLs are
        rejected because there is no trusted base URL to resolve them
        against. When this is ``None`` (the default), URL values are not
        checked and the historical property-name-only behavior is preserved.

        The check runs on the parsed tinycss2 token tree, so CSS escapes are
        resolved before the protocol is compared. It covers bare url tokens,
        string arguments of ``url()``, image-source strings in
        ``image-set()``/``image()`` and URLs nested inside other functions.
        A declaration containing a disallowed URL, a parse error, an
        unparseable URL argument or a ``var()``/``env()`` function is
        dropped wholesale. Strings that are not image sources (for example
        ``font-family`` or ``content`` values) are not treated as URLs.
    """

    def __init__(
        self,
        allowed_css_properties=ALLOWED_CSS_PROPERTIES,
        allowed_svg_properties=ALLOWED_SVG_PROPERTIES,
        allowed_url_protocols=None,
    ):
        self.allowed_css_properties = allowed_css_properties
        self.allowed_svg_properties = allowed_svg_properties
        if allowed_url_protocols is None:
            self.allowed_url_protocols = None
        else:
            self.allowed_url_protocols = frozenset(
                protocol.lower() for protocol in allowed_url_protocols
            )

    def sanitize_css(self, style):
        """Sanitizes css in style tags"""
        parsed = tinycss2.parse_declaration_list(style)

        if not parsed:
            return ""

        new_tokens = []
        for token in parsed:
            if token.type == "declaration":
                if (
                    token.lower_name in self.allowed_css_properties
                    or token.lower_name in self.allowed_svg_properties
                ) and self._declaration_value_is_allowed(token.value):
                    new_tokens.append(token)
            elif token.type in ("comment", "whitespace"):
                if new_tokens and new_tokens[-1].type != token.type:
                    new_tokens.append(token)

            # NOTE(willkg): We currently don't handle AtRule or ParseError and
            # so both get silently thrown out

        if not new_tokens:
            return ""

        return tinycss2.serialize(new_tokens).strip()

    def _declaration_value_is_allowed(self, tokens):
        """Return whether every URL in a declaration value is allowed.

        When no URL protocol policy is configured this always returns True,
        preserving the historical property-name-only behavior.
        """
        if self.allowed_url_protocols is None:
            return True
        return self._component_values_are_allowed(tokens)

    def _component_values_are_allowed(self, tokens, image_source_strings=False):
        for token in tokens:
            if not self._component_value_is_allowed(token, image_source_strings):
                return False
        return True

    def _component_value_is_allowed(self, token, image_source_strings):
        # Parse errors include bad-url and bad-string tokens; a declaration
        # containing one is dropped wholesale instead of partially serialized.
        if token.type == "error":
            return False

        if token.type == "url":
            return _url_is_allowed(token.value, self.allowed_url_protocols)

        if token.type == "string":
            # Only strings that the CSS grammar treats as image sources are
            # URLs. Font names, content strings and type() arguments are not.
            if image_source_strings:
                return _url_is_allowed(token.value, self.allowed_url_protocols)
            return True

        if token.type == "function":
            return self._function_is_allowed(token)

        if image_source_strings:
            return False

        if token.type in ("() block", "[] block", "{} block"):
            return self._component_values_are_allowed(
                token.content, image_source_strings=image_source_strings
            )

        return True

    def _function_is_allowed(self, function):
        lower_name = function.lower_name

        # Substitution functions can resolve to any value (including a URL)
        # at use time, so they cannot be checked against the policy.
        if lower_name in SUBSTITUTION_FUNCTIONS:
            return False

        if lower_name == "url":
            return self._url_function_is_allowed(function.arguments)

        image_source_strings = lower_name in (
            "image-set",
            "-webkit-image-set",
        )
        if image_source_strings:
            return self._image_set_function_is_allowed(function)
        if lower_name == "image":
            return self._image_function_is_allowed(function)
        return self._component_values_are_allowed(
            function.arguments,
            image_source_strings=image_source_strings,
        )

    def _image_set_function_is_allowed(self, function):
        for token in function.arguments:
            if token.type in IMAGE_SET_MARKER_TYPES:
                continue
            if token.type == "function" and token.lower_name == "type":
                # type() holds MIME strings, not image sources; recurse so
                # nested var()/env() and parse errors are still rejected.
                if not self._component_values_are_allowed(token.arguments):
                    return False
                continue
            if token.type == "function":
                # url() and other nested functions are validated against the
                # same policy; var()/env() and bad tokens are rejected there.
                if not self._function_is_allowed(token):
                    return False
                continue
            if token.type == "url":
                if not _url_is_allowed(token.value, self.allowed_url_protocols):
                    return False
                continue
            if token.type == "string":
                if not _url_is_allowed(token.value, self.allowed_url_protocols):
                    return False
                continue
            return False
        return True

    def _image_function_is_allowed(self, function):
        # image() takes an image-source string plus optional direction and
        # color arguments. Strings are URLs; the other arguments are not,
        # but nested functions (including var()/env()) are still recursed.
        first_source = next(
            (
                token
                for token in function.arguments
                if token.type not in ("whitespace", "comment")
            ),
            None,
        )
        # The image source must be an explicit string or a url()/url token;
        # anything else (for example a protocol-relative //host sequence)
        # cannot be interpreted as a safe URL here.
        if first_source is None or first_source.type not in (
            "string",
            "url",
            "function",
        ):
            return False
        for token in function.arguments:
            if token.type == "url":
                if not _url_is_allowed(token.value, self.allowed_url_protocols):
                    return False
                continue
            if token.type == "string":
                if not _url_is_allowed(token.value, self.allowed_url_protocols):
                    return False
                continue
            if not self._component_value_is_allowed(token, False):
                return False
        return True

    def _url_function_is_allowed(self, arguments):
        # url() takes a single URL argument. A quoted string is the parsed
        # URL; any other shape (multiple strings, nested functions, bad
        # tokens) is unparseable as a URL and must be rejected.
        significant = [
            token for token in arguments if token.type not in ("whitespace", "comment")
        ]
        if len(significant) != 1 or significant[0].type != "string":
            return False
        return _url_is_allowed(significant[0].value, self.allowed_url_protocols)
