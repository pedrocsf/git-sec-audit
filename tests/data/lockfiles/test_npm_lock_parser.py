import json

import pytest

from data.lockfiles.npm_lock_parser import NpmLockParser
from domain.entities.dependency_version import LockedPackage
from domain.entities.ecosystem import NPM_ECOSYSTEM
from domain.errors import LockfileParseError


def npm(name, version):
    return LockedPackage(NPM_ECOSYSTEM, name, version)


def test_supports_only_package_lock_basename():
    parser = NpmLockParser()
    assert parser.supports("package-lock.json")
    assert parser.supports("web/package-lock.json")
    assert not parser.supports("package.json")


def test_modern_lockfile_handles_scopes_nesting_links_and_duplicates():
    content = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/left-pad": {"version": "1.3.0"},
                "node_modules/@scope/pkg": {"version": "2.0.0"},
                "node_modules/a/node_modules/left-pad": {"version": "1.1.0"},
                "node_modules/b/node_modules/left-pad": {"version": "1.1.0"},
                "node_modules/@scope/pkg/node_modules/@other/inner": {"version": "0.5.0"},
                "node_modules/linked": {"resolved": "../linked", "link": True},
                "node_modules/alias": {"name": "real-name", "version": "4.0.0"},
            },
        }
    )
    assert NpmLockParser().parse(content) == [
        npm("left-pad", "1.3.0"),
        npm("@scope/pkg", "2.0.0"),
        npm("left-pad", "1.1.0"),
        npm("@other/inner", "0.5.0"),
        npm("real-name", "4.0.0"),
    ]


def test_legacy_lockfile_traverses_recursively():
    content = json.dumps(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "@scope/pkg": {
                    "version": "1.0.0",
                    "dependencies": {"left-pad": {"version": "1.1.0"}},
                },
                "left-pad": {"version": "1.3.0"},
                "dup": {
                    "version": "1.0.0",
                    "dependencies": {"left-pad": {"version": "1.3.0"}},
                },
            },
        }
    )
    assert NpmLockParser().parse(content) == [
        npm("@scope/pkg", "1.0.0"),
        npm("left-pad", "1.1.0"),
        npm("left-pad", "1.3.0"),
        npm("dup", "1.0.0"),
    ]


def test_invalid_json_raises():
    with pytest.raises(LockfileParseError):
        NpmLockParser().parse("{not json")


def test_unexpected_structure_raises():
    with pytest.raises(LockfileParseError):
        NpmLockParser().parse("[]")
