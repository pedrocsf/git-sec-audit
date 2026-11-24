import pytest

from domain.entities.semantic_version import SemanticVersion


@pytest.mark.parametrize(
    "text, expected",
    [
        ("1.2.3", SemanticVersion(1, 2, 3)),
        (" v1.2.3 ", SemanticVersion(1, 2, 3)),
        ("^1.2.3", SemanticVersion(1, 2, 3)),
        ("~1.2.3", SemanticVersion(1, 2, 3)),
        (">=1.2.3", SemanticVersion(1, 2, 3)),
        ("=1.2.3", SemanticVersion(1, 2, 3)),
        ("1", SemanticVersion(1, 0, 0)),
        ("1.2", SemanticVersion(1, 2, 0)),
        ("1.2.3+build.5", SemanticVersion(1, 2, 3)),
        ("1.2.3-beta.1", SemanticVersion(1, 2, 3, ("beta", "1"))),
    ],
)
def test_parse_valid(text, expected):
    assert SemanticVersion.parse(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "1.2.3.4", "1.x", "any"])
def test_parse_invalid(text):
    assert SemanticVersion.parse(text) is None


def test_ordering_follows_semver_precedence():
    ordered = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.1.0",
        "2.0.0",
    ]
    versions = [SemanticVersion.parse(text) for text in ordered]
    assert sorted(reversed(versions)) == versions


def test_numeric_comparison_not_lexicographic():
    assert SemanticVersion.parse("1.10.0") > SemanticVersion.parse("1.9.0")


def test_is_prerelease():
    assert SemanticVersion.parse("1.0.0-rc.1").is_prerelease
    assert not SemanticVersion.parse("1.0.0").is_prerelease
