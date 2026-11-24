from domain.entities.module_path import resolve_module


def test_feature_path_uses_three_segments():
    assert resolve_module("lib/features/login/ui/screen.dart") == "lib/features/login"


def test_apps_path_uses_three_segments():
    assert resolve_module("lib/apps/partner_mobile/main.dart") == "lib/apps/partner_mobile"


def test_default_depth_two():
    assert resolve_module("lib/core/utils/helper.dart") == "lib/core"


def test_custom_depth():
    assert resolve_module("a/b/c/d.py", depth=3) == "a/b/c"


def test_shallow_directory():
    assert resolve_module("src/file.py") == "src"


def test_root_file():
    assert resolve_module("README.md") == "(root)"
