from datetime import UTC, datetime

from domain.entities.finding_lifecycle import FindingKind
from presentation.controllers.history_controller import HistoryController
from presentation.controllers.patch_lag_controller import PatchLagController
from presentation.controllers.patterns_controller import PatternsController
from presentation.controllers.report_controller import ReportController
from presentation.controllers.run_options import RunOptions
from presentation.controllers.secrets_controller import SecretsController

AS_OF = datetime(2024, 6, 1, tzinfo=UTC)


class Recorder:
    def __init__(self):
        self.calls = []


class FakeUseCase:
    def __init__(self, recorder, name, result=None):
        self._recorder = recorder
        self._name = name
        self._result = result

    def execute(self, request=None):
        self._recorder.calls.append((self._name, request))
        return self._result


class FakeView:
    def __init__(self, recorder, name="view"):
        self._recorder = recorder
        self._name = name

    def __getattr__(self, method):
        def record(*arguments):
            self._recorder.calls.append((f"{self._name}.{method}", arguments))
            return arguments[1] if method == "render" else None

        return record


class FakeExportView(FakeView):
    def write_csv(self, report, output_dir):
        self._recorder.calls.append(("export.write_csv", (report, output_dir)))
        return [f"{output_dir}/a.csv"]


class Lifecycle:
    def __init__(self, kind):
        self.kind = kind


def build_options(output_dir="out"):
    return RunOptions("repo", "main", True, AS_OF, "main", None, output_dir, True, False)


def names(recorder):
    return [name for name, _ in recorder.calls]


def test_history_controller_syncs_and_renders():
    recorder = Recorder()
    HistoryController(FakeUseCase(recorder, "sync", ["c"]), FakeView(recorder)).run(
        "repo", "main", True
    )
    assert names(recorder) == ["sync", "view.render_commits"]
    assert recorder.calls[1][1] == (["c"],)
    request = recorder.calls[0][1]
    assert (request.repository_name, request.branch, request.first_parent) == (
        "repo",
        "main",
        True,
    )


def test_patch_lag_controller_order():
    recorder = Recorder()
    PatchLagController(
        FakeUseCase(recorder, "sync"),
        FakeUseCase(recorder, "timeline", ["v"]),
        FakeUseCase(recorder, "lag", ["r"]),
        FakeUseCase(recorder, "libyears", ["p"]),
        FakeView(recorder),
    ).run(build_options())
    assert names(recorder) == [
        "sync",
        "timeline",
        "view.render_dependency_timeline",
        "lag",
        "libyears",
        "view.render_patch_lag",
    ]
    assert recorder.calls[-1][1] == (["r"], ["p"])


def test_secrets_controller_order_and_filter():
    recorder = Recorder()
    lifecycles = [Lifecycle(FindingKind.SECRET), Lifecycle(FindingKind.INSECURE_PATTERN)]
    SecretsController(
        FakeUseCase(recorder, "sync"),
        FakeUseCase(recorder, "scan", ["f"]),
        FakeUseCase(recorder, "track"),
        FakeUseCase(recorder, "attribute", lifecycles),
        FakeView(recorder),
    ).run(build_options())
    assert names(recorder) == [
        "sync",
        "scan",
        "view.render_secret_findings",
        "track",
        "attribute",
        "view.render_lifecycles",
    ]
    assert recorder.calls[-1][1] == ([lifecycles[0]], AS_OF)


def test_patterns_controller_order_and_filter():
    recorder = Recorder()
    lifecycles = [Lifecycle(FindingKind.SECRET), Lifecycle(FindingKind.INSECURE_PATTERN)]
    PatternsController(
        FakeUseCase(recorder, "sync"),
        FakeUseCase(recorder, "scan", ["f"]),
        FakeUseCase(recorder, "track"),
        FakeUseCase(recorder, "attribute", lifecycles),
        FakeView(recorder),
    ).run(build_options())
    assert names(recorder) == [
        "sync",
        "scan",
        "view.render_pattern_findings",
        "track",
        "attribute",
        "view.render_lifecycles",
    ]
    assert recorder.calls[-1][1] == ([lifecycles[1]], AS_OF)


def test_report_controller_writes_outputs(tmp_path):
    recorder = Recorder()
    output_dir = str(tmp_path / "out")
    ReportController(
        FakeUseCase(recorder, "build", "REPORT"),
        FakeView(recorder, "console"),
        FakeView(recorder, "html"),
        FakeExportView(recorder, "export"),
    ).run(output_dir, AS_OF, True, False)
    assert names(recorder) == [
        "build",
        "console.render_report",
        "html.render",
        "export.write_json",
        "export.write_csv",
        "console.render_message",
        "console.render_message",
        "console.render_message",
    ]
    request = recorder.calls[0][1]
    assert (request.as_of, request.include_authors, request.anonymize_authors) == (
        AS_OF,
        True,
        False,
    )
