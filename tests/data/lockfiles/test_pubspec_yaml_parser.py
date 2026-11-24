import pytest

from data.lockfiles.pubspec_yaml_parser import PubspecYamlParser
from domain.entities.dependency_version import LockedPackage
from domain.entities.ecosystem import PUB_ECOSYSTEM
from domain.errors import LockfileParseError

MANIFEST_CONTENT = """
name: app
dependencies:
  flutter:
    sdk: flutter
  caret: ^1.2.3
  ranged: ">=1.0.0 <2.0.0"
  exact: 1.2.3
  anything: any
  nothing:
  mapped:
    version: ^2.0.0
  hosted_pkg:
    hosted: https://example.com
    version: ^3.1.0
  local:
    path: ../local
  gitpkg:
    git: https://example.com/x.git
dev_dependencies:
  test: ^1.0.0
"""


def approximated(name, version):
    return LockedPackage(PUB_ECOSYSTEM, name, version, approximated=True)


def test_supports_only_pubspec_yaml_basename():
    parser = PubspecYamlParser()
    assert parser.supports("pubspec.yaml")
    assert parser.supports("a/b/pubspec.yaml")
    assert not parser.supports("pubspec.lock")


def test_extracts_lowest_version_from_constraints():
    assert PubspecYamlParser().parse(MANIFEST_CONTENT) == [
        approximated("caret", "1.2.3"),
        approximated("ranged", "1.0.0"),
        approximated("exact", "1.2.3"),
        approximated("mapped", "2.0.0"),
        approximated("hosted_pkg", "3.1.0"),
        approximated("test", "1.0.0"),
    ]


def test_empty_content_returns_empty_list():
    assert PubspecYamlParser().parse("") == []


def test_invalid_yaml_raises():
    with pytest.raises(LockfileParseError):
        PubspecYamlParser().parse("dependencies: [unclosed")


def test_unexpected_structure_raises():
    with pytest.raises(LockfileParseError):
        PubspecYamlParser().parse("dependencies:\n  - a\n")
