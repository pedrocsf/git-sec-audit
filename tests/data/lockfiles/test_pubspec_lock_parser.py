import pytest

from data.lockfiles.pubspec_lock_parser import PubspecLockParser
from domain.entities.dependency_version import LockedPackage
from domain.entities.ecosystem import PUB_ECOSYSTEM
from domain.errors import LockfileParseError

LOCK_CONTENT = """
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  local:
    dependency: "direct main"
    description:
      path: "../local"
    source: path
    version: "0.1.0"
  gitpkg:
    dependency: "direct main"
    description:
      url: "https://example.com/x.git"
    source: git
    version: "0.2.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
"""


def test_supports_only_pubspec_lock_basename():
    parser = PubspecLockParser()
    assert parser.supports("pubspec.lock")
    assert parser.supports("apps/x/pubspec.lock")
    assert not parser.supports("pubspec.yaml")


def test_parses_only_hosted_packages():
    assert PubspecLockParser().parse(LOCK_CONTENT) == [
        LockedPackage(PUB_ECOSYSTEM, "http", "1.2.0")
    ]


def test_empty_content_returns_empty_list():
    assert PubspecLockParser().parse("") == []


def test_invalid_yaml_raises():
    with pytest.raises(LockfileParseError):
        PubspecLockParser().parse("packages: [unclosed")


def test_unexpected_structure_raises():
    with pytest.raises(LockfileParseError):
        PubspecLockParser().parse("- a\n- b\n")
    with pytest.raises(LockfileParseError):
        PubspecLockParser().parse("packages:\n  http: 1.0.0\n")
