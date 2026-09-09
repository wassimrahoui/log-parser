"""JSON malformed corpus (build plan §26)."""

CORPUS = [
    ('{"a": 1', "TRUNCATED_JSON"),
    ('{"a": 1, "a": 2, "a": 3}', "TRIPLE_DUPLICATE_KEYS"),
    ('[1, 2, 3]', "TOP_LEVEL_ARRAY"),
    ('"just a string"', "TOP_LEVEL_SCALAR"),
    ("null", "TOP_LEVEL_NULL"),
    ('{"deep": ' + '{"x": ' * 40 + "1" + "}" * 40 + "}", "DEPTH_OVER_LIMIT"),
    ('{"ts": "not-a-timestamp", "src": "999.999.1.1", "port": "notaport"}',
     "INVALID_TYPED_VALUES"),
    ("", "EMPTY"),
    ("{bad json}", "INVALID_SYNTAX"),
    ('{"nested": {"a": {"b": {"c": [1,2,{"d": 5}]}}}}', "NESTED_ARRAYS"),
]
